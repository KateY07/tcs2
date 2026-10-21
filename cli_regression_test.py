"""Test shipping argument failures and new syntax over real TCP with isolated identities."""
import concurrent.futures
import json
import re
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

exe, harness = (Path(p).resolve() for p in sys.argv[1:3])


def run(binary, *args, expected=0):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True,
                            encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == expected, (args, result.stdout, result.stderr)
    return result.stdout


def run_any(binary, *args):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True,
                            encoding="utf-8", errors="replace", timeout=60)
    return result


for args in [("alipc", "exec"), ("alipc", "upload"),
             ("alipc", "exec", "print(1)", "--file", "test.py"),
             ("alipc", "health", "--port", "abc"), ()]:
    rejected = run_any(exe, *args)
    assert rejected.returncode == 255, (args, rejected.returncode, rejected.stderr)
    assert "usage: tcs <host>" in rejected.stderr and "tcs --help" in rejected.stderr, rejected.stderr
    assert "   at " not in rejected.stderr, "argument errors must not print stack traces"
    assert len(rejected.stderr) < 700, len(rejected.stderr)
print("PASS AOT CLI rejects invalid syntax with exit 255 and a compact usage, no stack trace")

with tempfile.TemporaryDirectory(prefix="tcs-cli-wire-") as directory:
    root = Path(directory)
    client, host, auth = root / "client", root / "host", root / "authorized_keys"
    run(harness, "--generate-host-key", client)
    run(harness, "--generate-host-key", host)
    auth.write_bytes(Path(str(client) + ".pub").read_bytes())
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with (root / "server.log").open("w", encoding="utf-8") as log:
        server = subprocess.Popen([str(harness), "--tcsd", "--authorized-keys", str(auth),
                                   "--host-key", str(host), "--data", str(root / "data"),
                                   "--port", str(port), "--python", sys.executable], stdout=log, stderr=log)
        try:
            for attempt in range(100):
                assert server.poll() is None, "server exited"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if attempt == 99:
                        raise
                    time.sleep(0.05)

            def request(address, *args):
                return json.loads(run(harness, "--cli-fixture", client, str(host) + ".pub",
                                      address, *args, "--port", port, "--json"))

            def fixture(*args, address="127.0.0.1"):
                return run_any(harness, "--cli-fixture", client, str(host) + ".pub", address, *args, "--port", port)

            for address in ("127.0.0.1", "::1"):
                assert request(address, "health") == {"status": "ok"}
                result = request(address, "exec", "print('hello')")
                assert result["ExitCode"] == 0 and result["Stdout"].strip() == "hello", result
            script = root / "test space.py"
            script.write_text("print('from-file')\n", encoding="utf-8-sig")
            file_result = request("127.0.0.1", "exec", "--file", script)
            assert file_result["ExitCode"] == 0 and file_result["Stdout"].strip() == "from-file", file_result
            upload = root / "demo.txt"
            upload.write_bytes(b"exact bytes\r\n" * 100)
            saved = request("::1", "upload", upload)["saved"][0]
            assert (root / "data" / "uploads" / saved).read_bytes() == upload.read_bytes()

            def concurrent_request(index):
                result = request("127.0.0.1", "exec", f"print('task-{index}')")
                assert result["ExitCode"] == 0 and result["Stdout"].strip() == f"task-{index}", result

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(concurrent_request, range(8)))
            quiet = fixture("exec", "print('hello')")
            assert quiet.returncode == 0 and quiet.stdout.strip() == "hello" and quiet.stderr == "", quiet
            failed = fixture("exec", "import sys; print('partial'); sys.exit(3)")
            assert failed.returncode == 3 and failed.stdout.strip() == "partial", failed
            assert failed.stderr.replace("\r\n", "\n") == "tcs: exit=3\n", repr(failed.stderr)
            boom = fixture("exec", "raise RuntimeError('boom')")
            assert boom.returncode == 1 and "RuntimeError: boom" in boom.stderr, boom
            assert boom.stderr.rstrip().splitlines()[-1] == "tcs: exit=1", boom.stderr
            noisy = fixture("exec", "import sys; sys.stderr.write('warn')")
            assert noisy.returncode == 0 and noisy.stderr == "warn", noisy
            as_json = fixture("exec", "import sys; sys.exit(3)", "--json")
            assert as_json.returncode == 0 and json.loads(as_json.stdout)["ExitCode"] == 3
            meta = fixture("exec", "print('ok')", "--meta")
            assert re.fullmatch(r"tcs: exit=0 task=\d+ms total=\d+ms out=\d+ err=0\s*", meta.stderr), repr(meta.stderr)
            health = fixture("health")
            assert health.returncode == 0 and json.loads(health.stdout) == {"status": "ok"}
            print("PASS output contract: silent success, remote exit code, one tcs: line on failure, --json, --meta")

            flood = fixture("exec", "print('x' * 200000)")
            assert flood.returncode == 0 and len(flood.stdout) < 17000 and "[tcs:" in flood.stdout, len(flood.stdout)
            assert "stdout-omitted=" in flood.stderr, flood.stderr
            unlimited = fixture("exec", "print('x' * 200000)", "--max-output", "0")
            assert len(unlimited.stdout.strip()) == 200000 and unlimited.stderr == ""
            small = fixture("exec", "print('y' * 5000)", "--max-output", "1000")
            assert 1000 <= len(small.stdout) < 1300 and "stdout-omitted=" in small.stderr, len(small.stdout)
            tail = fixture("exec", "print('a' * 100000); print('THE-END')", "--max-output", "2000")
            assert "THE-END" in tail.stdout, "tail must be kept: errors usually come last"
            big = fixture("exec", "print('z' * 20000000)")
            assert big.returncode == 0 and len(big.stdout) < 17000, "20 MB of output must be capped, not buffered whole"
            print("PASS output cap: default 16000 chars, head+tail kept, --max-output N/0, 20 MB flood bounded")

            print("PASS new syntax: dual-stack health/exec, exec --file with BOM/spaces, exact upload, 8 concurrent exec")
        finally:
            server.terminate()
            server.wait(timeout=10)

print("ALL CLI REGRESSION TESTS PASSED")
