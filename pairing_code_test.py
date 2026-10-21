"""Pairing by one-time code over real TCP with isolated identities (test harness paths only).

usage: pairing_code_test.py <tcs-test.exe>
Covers: correct code, wrong code, per-address rate limit, lockout after repeated failures, single use, expiry,
"not pairing", automatic authorization reload (no daemon restart), the explicit rejection of an unauthorized
controller, and the audit trail of all of it.
"""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

harness = Path(sys.argv[1]).resolve()


def run(*args, expected=None):
    result = subprocess.run([str(harness), *map(str, args)], capture_output=True, encoding="utf-8", errors="replace", timeout=60)
    if expected is not None:
        assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
    return result


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Daemon:
    def __init__(self, root, name, port, *extra):
        self.dir = root / name
        self.dir.mkdir()
        self.client, self.host, self.auth = self.dir / "client", self.dir / "host", self.dir / "authorized_keys"
        self.known = self.dir / "known"
        self.port = port
        run("--generate-host-key", self.client, expected=0)
        run("--generate-host-key", self.host, expected=0)
        self.log = (self.dir / "daemon.log").open("w", encoding="utf-8")
        self.proc = subprocess.Popen([str(harness), "--tcsd", "--authorized-keys", str(self.auth), "--host-key", str(self.host),
                                      "--data", str(self.dir / "data"), "--port", str(port), "--python", sys.executable, *map(str, extra)],
                                     stdout=self.log, stderr=self.log)
        for attempt in range(100):
            assert self.proc.poll() is None, "daemon exited"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
                if attempt == 99:
                    raise

    def pair(self, code):
        return run("--pair-client", self.client, self.known, "127.0.0.1", self.port, code)

    def health(self):
        return run("--cli-fixture", self.client, str(self.host) + ".pub", "127.0.0.1", "health", "--port", self.port, "--json")

    def events(self):
        path = self.dir / "data" / "tcs-audit.log"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.log.close()


with tempfile.TemporaryDirectory(prefix="tcs-paircode-") as directory:
    root = Path(directory)

    # --- normal flow: wrong code, rate limit, right code, no restart needed, single use
    d = Daemon(root, "main", free_port(), "--pair", "--pair-code", "481937", "--pair-seconds", "30")
    try:
        bad = d.pair("111-111")
        assert bad.returncode == 11 and bad.stdout.startswith("BAD_CODE"), (bad.returncode, bad.stdout, bad.stderr)
        quick = d.pair("481-937")
        assert quick.returncode == 13 and quick.stdout.startswith("RATE_LIMITED") and "retryAfter=2" in quick.stdout, quick.stdout
        assert not d.auth.exists() or d.auth.read_text() == "", "a refused pairing must not authorize anything"
        before = d.health()
        assert before.returncode != 0 and "not authorized" in (before.stdout + before.stderr).lower(), (before.stdout, before.stderr)
        print("PASS wrong code refused, one attempt every 2 s, unauthorized controller gets an explicit rejection")

        time.sleep(2.3)
        good = d.pair("481937")
        assert good.returncode == 0 and good.stdout.startswith("PAIRED SHA256:"), (good.stdout, good.stderr)
        assert Path(str(d.client) + ".pub").read_text().split()[1] in d.auth.read_text(), "controller key was not authorized"
        assert len(list(d.known.glob("*.pub"))) == 1, "host key was not pinned"
        after = d.health()
        assert after.returncode == 0 and json.loads(after.stdout) == {"status": "ok"}, (after.stdout, after.stderr)
        print("PASS correct code pairs both ways and works at once, without restarting the daemon")

        time.sleep(2.3)
        reuse = d.pair("481-937")
        assert reuse.returncode == 10 and reuse.stdout.startswith("NOT_PAIRING"), reuse.stdout
        print("PASS the code is single use: the window closed after success")

        exec_result = run("--cli-fixture", d.client, str(d.host) + ".pub", "127.0.0.1", "exec", "print(1)", "--port", d.port, expected=0)
        assert exec_result.stdout.strip() == "1"
    finally:
        d.stop()
    events = d.events()
    names = [e.get("event") or e.get("endpoint") for e in events]
    for expected in ("daemon-start", "pair-window-open", "pair-attempt", "pair-ok", "pair-window-close", "auth-denied", "auth-ok", "/v1/exec"):
        assert expected in names, (expected, names)
    denied = next(e for e in events if e.get("event") == "auth-denied")
    assert denied["result"] == "NOT_AUTHORIZED" and denied["source"] and denied["clientFingerprint"].startswith("SHA256:"), denied
    executed = next(e for e in events if e.get("endpoint") == "/v1/exec")
    assert executed["source"] and len(executed["scriptSha256"]) == 64 and "print(1)" not in json.dumps(executed), executed   # hash only, never the script text
    assert all(e["timestamp"] for e in events)
    assert "481937" not in (d.dir / "data" / "tcs-audit.log").read_text(encoding="utf-8"), "the code must never be logged"
    print("PASS audit trail: connections, denials with source and fingerprint, pairing events, script hash (never the code)")

    # --- brute force: repeated wrong codes lock the window and block the address, even for the right code afterwards
    d = Daemon(root, "brute", free_port(), "--pair", "--pair-code", "246810", "--pair-seconds", "30")
    try:
        results = []
        for guess in ("000001", "000002", "000003"):
            results.append(d.pair(guess))
            time.sleep(2.3)
        assert all(r.returncode == 11 for r in results), [r.stdout for r in results]
        late = d.pair("246810")
        assert late.returncode in (12, 13) and late.stdout.split()[0] in ("LOCKED", "RATE_LIMITED"), late.stdout
        assert not d.auth.exists() or d.auth.read_text() == "", "the right code must not work after lockout"
        assert d.health().returncode != 0
        locked = [e for e in d.events() if e.get("event") == "pair-window-close"]
        assert locked and locked[-1]["result"] == "LOCKED", locked
        print("PASS brute force: three wrong codes lock the window and the address; the right code is refused afterwards")
    finally:
        d.stop()

    # --- expiry and not-pairing
    d = Daemon(root, "expiry", free_port(), "--pair", "--pair-code", "135790", "--pair-seconds", "3")
    try:
        time.sleep(4.0)
        expired = d.pair("135790")
        assert expired.returncode == 15 and expired.stdout.startswith("EXPIRED"), expired.stdout
        print("PASS expiry: a code is refused after its window closed")
    finally:
        d.stop()
    d = Daemon(root, "closed", free_port())
    try:
        closed = d.pair("123456")
        assert closed.returncode == 10 and closed.stdout.startswith("NOT_PAIRING"), closed.stdout
        malformed = run("--pair-client", d.client, d.known, "127.0.0.1", d.port, "12ab56")
        assert malformed.returncode != 0
        print("PASS a daemon that is not pairing says NOT_PAIRING; malformed codes are rejected locally")
    finally:
        d.stop()
    # --- a key added to authorized_keys while the daemon runs (tcsd pairing import) works without a restart
    d = Daemon(root, "reload", free_port())
    try:
        assert d.health().returncode != 0
        d.auth.write_text(Path(str(d.client) + ".pub").read_text(), encoding="utf-8")
        ok = d.health()
        assert ok.returncode == 0 and json.loads(ok.stdout) == {"status": "ok"}, (ok.stdout, ok.stderr)
        assert any(e.get("event") == "authorized-reload" and e["result"] == "OK" for e in d.events())
        print("PASS authorized_keys changes are picked up automatically (no daemon restart)")
    finally:
        d.stop()
print("ALL PAIRING CODE TESTS PASSED")
