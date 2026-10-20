"""Measure TCS overhead relative to the task itself.

overhead = (time to run the script through tcs) - (time to run the same script with local python).
Transport is measured in-process (hot, loopback) by the test harness; process start is measured on the
published AOT binary with `tcs --help` (no network, no keys, touches nothing under %USERPROFILE%).

usage: overhead_test.py <harness.exe> [published tcs.exe] [--max-ms N]
"""
import json
from pathlib import Path
import socket
import statistics
import subprocess
import sys
import tempfile
import time

args = [a for a in sys.argv[1:] if not a.startswith("--max-ms")]
limit_ms = next((float(a.split("=")[1]) for a in sys.argv[1:] if a.startswith("--max-ms=")), None)
harness = Path(args[0]).resolve()
published = Path(args[1]).resolve() if len(args) > 1 else None
N = 15


def run(binary, *a):
    result = subprocess.run([str(binary), *map(str, a)], capture_output=True, encoding="utf-8", errors="replace", timeout=120)
    assert result.returncode == 0, (a, result.stdout, result.stderr)
    return result.stdout


def local_ms(script):
    samples = []
    for _ in range(N):
        start = time.perf_counter()
        subprocess.run([sys.executable, str(script)], capture_output=True, check=True)
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


rows = []
with tempfile.TemporaryDirectory(prefix="tcs-overhead-") as directory:
    root = Path(directory)
    client, host, auth = root / "client", root / "host", root / "authorized_keys"
    run(harness, "--generate-host-key", client)
    run(harness, "--generate-host-key", host)
    auth.write_bytes(Path(str(client) + ".pub").read_bytes())
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with (root / "server.log").open("w", encoding="utf-8") as log:
        server = subprocess.Popen([str(harness), "--tcsd", "--authorized-keys", str(auth), "--host-key", str(host),
                                   "--data", str(root / "data"), "--port", str(port), "--python", sys.executable],
                                  stdout=log, stderr=log)
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
            for name, source in (("pass (0 s task)", "pass\n"),
                                 ("sleep 0.5 s", "import time; time.sleep(0.5)\n"),
                                 ("sleep 2 s", "import time; time.sleep(2)\n")):
                script = root / "task.py"
                script.write_text(source, encoding="utf-8")
                base = local_ms(script)
                data = json.loads(run(harness, "--bench", client, str(host) + ".pub", "127.0.0.1", port, N, script))
                exec_first, exec_med = data["exec"][0], statistics.median(data["exec"][1:])
                rows.append((name, base, exec_med, exec_med - base, exec_first, statistics.median(data["health"][1:]), data["health"][0]))
        finally:
            server.terminate()
            server.wait(timeout=10)

start_ms = None
if published:
    samples = []
    for _ in range(N):
        start = time.perf_counter()
        subprocess.run([str(published), "--help"], capture_output=True, check=True)
        samples.append((time.perf_counter() - start) * 1000)
    start_ms = statistics.median(samples)

print(f"{'task':<16}{'local py':>10}{'via tcs':>10}{'overhead':>10}{'ovh %':>8}{'1st call':>10}{'health':>8}{'1st hlth':>9}   (ms, medians; hot in-process loopback)")
for name, base, remote, over, first, health, first_health in rows:
    print(f"{name:<16}{base:>10.0f}{remote:>10.0f}{over:>10.0f}{over / max(base, 1) * 100:>7.0f}%{first:>10.0f}{health:>8.0f}{first_health:>9.0f}")
if start_ms is not None:
    print(f"process start (published AOT `tcs --help`, wall): {start_ms:.0f} ms median -> add once per CLI call")
if limit_ms is not None:
    worst = max(r[3] for r in rows)
    assert worst <= limit_ms, f"overhead {worst:.0f} ms exceeds limit {limit_ms:.0f} ms"
    print(f"PASS overhead {worst:.0f} ms <= {limit_ms:.0f} ms")
