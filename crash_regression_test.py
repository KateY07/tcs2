"""Exercise transport failures through tests/TransportHarness.csproj; CLI restrictions use deployment_regression_test.py."""
import concurrent.futures
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


exe = Path(sys.argv[1]).resolve()


def run(*args, expected=0):
    result = subprocess.run([str(exe), *map(str, args)], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == expected, (args, result.returncode, result.stderr)
    if expected:
        assert "tcs: operation failed:" in result.stderr, result.stderr
        assert not result.stdout.strip(), result.stdout
    return result


with tempfile.TemporaryDirectory(prefix="tcs-crash-test-") as directory:
    root = Path(directory)
    client_key, host_key = root / "client", root / "host"
    run("--generate-host-key", client_key)
    run("--generate-host-key", host_key)
    shutil.copyfile(str(client_key) + ".pub", root / "authorized_keys")
    options = ["--tcs-client", "--client-key", str(client_key),
               "--server-key", str(host_key) + ".pub"]

    # A bound, non-listening local port reliably rejects TCP without external traffic.
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
        def refused(_):
            result = run(*options, "--host", "127.0.0.1", "--port", port, expected=1)
            assert "SocketException" in result.stderr, result.stderr
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(refused, range(12)))
    print("PASS 12 refused connections: clean exit 1 and visible error")
    run(*options, "--host", "tcs-regression.invalid", expected=1)
    run(*options, "--port", "invalid", expected=1)
    run(*options, "--operation", "upload", expected=1)
    run(*options, "--operation", "exec", "--script-base64", "%%%", expected=1)
    run("--generate-host-key", expected=1)
    run("--tcsd", "--host-key", root / "missing", expected=1)
    print("PASS DNS, arguments, upload path, base64, and daemon startup failures")

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            request = pool.submit(run, *options, "--host", "127.0.0.1", "--port", port, expected=1)
            listener.settimeout(10)
            peer, _ = listener.accept()
            with peer:
                peer.recv(4096)
            request.result()
    print("PASS peer disconnect during handshake")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with (root / "daemon.log").open("w") as log:
        daemon = subprocess.Popen([str(exe), "--tcsd", "--port", str(port),
                                   "--host-key", str(host_key), "--authorized-keys",
                                   str(root / "authorized_keys"), "--data", str(root),
                                   "--python", sys.executable], stdout=log, stderr=log)
        try:
            for attempt in range(100):
                assert daemon.poll() is None, "daemon exited during startup"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError as error:
                    if attempt == 99:
                        raise RuntimeError("daemon did not start") from error
                    time.sleep(0.05)
            run("--verify-install", port, client_key, str(host_key) + ".pub", root)
            print("PASS IPv4/IPv6 authenticated health, Python execution, upload integrity")
        finally:
            daemon.terminate()
            daemon.wait(timeout=10)
print("ALL CRASH REGRESSION TESTS PASSED")
