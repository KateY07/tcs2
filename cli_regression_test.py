"""Test shipping argument failures and new syntax over real TCP with isolated identities."""
import concurrent.futures
import json
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


for args in [("alipc", "exec"), ("alipc", "upload"),
             ("alipc", "exec", "print(1)", "--file", "test.py"),
             ("alipc", "health", "--port", "abc")]:
    run(exe, *args, expected=1)
print("PASS AOT CLI rejects invalid new syntax")

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
                                      address, *args, "--port", port))

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
            print("PASS new syntax: dual-stack health/exec, exec --file with BOM/spaces, exact upload, 8 concurrent exec")
        finally:
            server.terminate()
            server.wait(timeout=10)

print("ALL CLI REGRESSION TESTS PASSED")
