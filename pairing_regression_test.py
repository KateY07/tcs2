"""Exercise pairing imports and first-use host trust with isolated identities."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

exe = Path(sys.argv[1]).resolve()


def run(*args, expected=0):
    result = subprocess.run([str(exe), *map(str, args)], input="yes\n", capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
    return result


def available_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def read_exact(stream, length):
    result = b""
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError("truncated handshake")
        result += part
    return result


with tempfile.TemporaryDirectory(prefix="tcs-pairing-test-") as temporary:
    root = Path(temporary)
    client, host, other = root / "client", root / "host", root / "other"
    auth, pairing, known = root / "authorized_keys", root / "controller.tcs-pair", root / "known"
    run("--generate-host-key", client)
    run("pairing", "export", "--client-key", client, "--output", pairing)
    document = json.loads(pairing.read_text(encoding="utf-8"))
    assert set(document) == {"type", "version", "publicKey", "fingerprint"}
    assert "PRIVATE" not in pairing.read_text(encoding="utf-8")
    before = pairing.read_bytes()
    run("pairing", "export", "--client-key", client, "--output", pairing, expected=1)
    assert pairing.read_bytes() == before
    import_args = ["--tcsd", "pairing", "import", pairing, "--authorized-keys", auth, "--host-key", host]
    run(*import_args, "--trust-fingerprint", "SHA256:wrong", expected=1)
    assert not auth.exists() and not host.exists()
    run(*import_args, expected=1)
    assert not auth.exists() and not host.exists()
    run(*import_args, "--trust-fingerprint", document["fingerprint"])
    host_bytes, auth_bytes = host.read_bytes(), auth.read_bytes()
    repeated = run(*import_args)
    assert host.read_bytes() == host_bytes and auth.read_bytes() == auth_bytes
    print("PASS pure-data export; refusal has no authorization side effect; import is idempotent")

    invalid = root / "invalid.tcs-pair"
    variants = [dict(document, script="echo malicious"), dict(document, version=2),
                dict(document, fingerprint="SHA256:wrong")]
    for variant in variants:
        invalid.write_text(json.dumps(variant), encoding="utf-8")
        run("--tcsd", "pairing", "import", invalid, "--authorized-keys", auth, "--host-key", host,
            "--trust-fingerprint", document["fingerprint"], expected=1)
        assert auth.read_bytes() == auth_bytes and host.read_bytes() == host_bytes
    invalid.write_text(pairing.read_text().replace('"version": 1', '"version": 1, "version": 1'), encoding="utf-8")
    run("--tcsd", "pairing", "import", invalid, "--authorized-keys", auth, "--host-key", host, expected=1)
    print("PASS unknown fields, versions, changed fingerprints and duplicate fields rejected")

    import base64
    host_blob = base64.b64decode(Path(str(host) + ".pub").read_text().split()[1])
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(host_blob).digest()).decode().rstrip("=")
    port = available_port()
    log = (root / "server.log").open("w", encoding="utf-8")

    def start_server(key):
        process = subprocess.Popen([str(exe), "--tcsd", "--host-key", str(key), "--authorized-keys", str(auth),
                                    "--port", str(port), "--data", str(root / "data"), "--python", sys.executable],
                                   stdout=log, stderr=log)
        for attempt in range(100):
            assert process.poll() is None, "daemon exited"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return process
            except OSError:
                if attempt == 99:
                    process.terminate()
                    process.wait(timeout=10)
                    raise
                time.sleep(0.05)

    daemon = start_server(host)
    options = ["--host", "127.0.0.1", "--port", port, "--client-key", client, "--known-hosts", known]
    try:
        run(*options, expected=1)
        assert not known.exists()
        run(*options, "--trust-fingerprint", "SHA256:wrong", expected=1)
        assert not known.exists()
        with socket.socket() as proxy:
            proxy.bind(("127.0.0.1", 0))
            proxy.listen()
            proxy.settimeout(10)
            proxy_port = proxy.getsockname()[1]

            def corrupt_signature():
                peer, _ = proxy.accept()
                with peer, socket.create_connection(("127.0.0.1", port), timeout=10) as upstream:
                    peer.settimeout(10)
                    prefix = read_exact(peer, 13)
                    hello = prefix + read_exact(peer, struct.unpack(">I", prefix[-4:])[0] + 64)
                    upstream.sendall(hello)
                    header = read_exact(upstream, 13)
                    rest = read_exact(upstream, struct.unpack(">I", header[-4:])[0] + 64)
                    size = read_exact(upstream, 4)
                    signature = bytearray(read_exact(upstream, struct.unpack(">I", size)[0]))
                    signature[-1] ^= 1
                    peer.sendall(header + rest + size + signature)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(corrupt_signature)
                result = run("--host", "127.0.0.1", "--port", proxy_port, "--client-key", client,
                             "--known-hosts", known, "--trust-fingerprint", fingerprint, expected=1)
                future.result(timeout=15)
                assert "invalid server signature" in result.stderr
                assert not known.exists()
        print("PASS redirected yes, wrong fingerprint, and forged server signature cannot establish trust")
        accepted = run(*options, "--trust-fingerprint", fingerprint)
        assert json.loads(accepted.stdout)["status"] == "ok"
        pins = list(known.glob("*.pub"))
        assert len(pins) == 1
        pin_bytes = pins[0].read_bytes()
        assert json.loads(run(*options).stdout)["status"] == "ok"
        result = json.loads(run(*options, "--operation", "exec", "--script", "print('paired')").stdout)
        assert result["ExitCode"] == 0 and result["Stdout"].strip() == "paired"
        print("PASS first verified connection saves host key; later health and execution require no confirmation")
        daemon.terminate()
        daemon.wait(timeout=10)
        run("--generate-host-key", other)
        daemon = start_server(other)
        changed = run(*options, expected=1)
        assert "server host-key fingerprint mismatch" in changed.stderr
        assert pins[0].read_bytes() == pin_bytes
        print("PASS changed host identity rejected without replacing the saved key")
    finally:
        if daemon.poll() is None:
            daemon.terminate()
            daemon.wait(timeout=10)
        log.close()
print("ALL PAIRING REGRESSION TESTS PASSED")
