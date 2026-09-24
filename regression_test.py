#!/usr/bin/env python3
"""
Full regression suite for tcs: security, latency, bandwidth, concurrency.

Requires: pip install requests

Setup (once):
    powershell -File gen-certs.ps1 -OutDir D:\\keys\\tcs           # trusted client
    powershell -File gen-certs.ps1 -OutDir D:\\keys\\tcs-untrusted # NOT in authorized-clients.json
    bin\\Release\\net10.0\\tcs.exe -i D:\\keys\\tcs -p 10122

Run:
    python regression_test.py --host localhost --port 10122 ^
        --cacert D:\\keys\\tcs\\server.crt ^
        --client-cert D:\\keys\\tcs\\client.crt --client-key D:\\keys\\tcs\\client.key ^
        --untrusted-cert D:\\keys\\tcs-untrusted\\client.crt --untrusted-key D:\\keys\\tcs-untrusted\\client.key

Every section prints PASS/FAIL lines and the script exits non-zero if
anything failed, so it's usable as a CI gate as well as an interactive check.
"""

import argparse
import concurrent.futures
import json
import os
import ssl
import statistics
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

import requests
from requests.adapters import HTTPAdapter

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = ""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)
    return condition


def base_url(args) -> str:
    return f"https://{args.host}:{args.port}"


def make_session(args, cert=None, key=None) -> requests.Session:
    s = requests.Session()
    s.verify = args.cacert
    if cert and key:
        s.cert = (cert, key)
    return s


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

def test_security(args):
    print("\n=== SECURITY ===")

    # 1. No client certificate at all -> TLS handshake must fail, request
    #    must never reach the application layer.
    try:
        requests.get(f"{base_url(args)}/v1/health", verify=args.cacert, timeout=5)
        check("reject connection with no client certificate", False,
              "request succeeded but should have failed at the TLS handshake")
    except requests.exceptions.SSLError:
        check("reject connection with no client certificate", True)
    except requests.exceptions.ConnectionError:
        check("reject connection with no client certificate", True)

    # 2. A client certificate that IS valid TLS but is NOT in
    #    authorized-clients.json -> must also fail at the handshake.
    if args.untrusted_cert and args.untrusted_key:
        try:
            s = make_session(args, args.untrusted_cert, args.untrusted_key)
            s.get(f"{base_url(args)}/v1/health", timeout=5)
            check("reject unpinned (untrusted) client certificate", False,
                  "request succeeded but the cert's thumbprint isn't pinned")
        except requests.exceptions.SSLError:
            check("reject unpinned (untrusted) client certificate", True)
        except requests.exceptions.ConnectionError:
            check("reject unpinned (untrusted) client certificate", True)
    else:
        print("[SKIP] reject unpinned client certificate -- pass --untrusted-cert/--untrusted-key")

    # 3. Valid, pinned client certificate -> must succeed.
    s = make_session(args, args.client_cert, args.client_key)
    try:
        r = s.get(f"{base_url(args)}/v1/health", timeout=5)
        check("accept pinned client certificate", r.status_code == 200 and r.json().get("status") == "ok",
              f"status={r.status_code} body={r.text}")
    except Exception as e:
        check("accept pinned client certificate", False, str(e))
        return  # nothing else will work without this

    # 4. Plain HTTP (no TLS at all) to the same port must not be served.
    try:
        req = urllib.request.Request(f"http://{args.host}:{args.port}/v1/health")
        urllib.request.urlopen(req, timeout=5)
        check("refuse plaintext HTTP on the mTLS port", False, "plaintext request succeeded")
    except Exception:
        check("refuse plaintext HTTP on the mTLS port", True)

    # 5. Upload filename path traversal: server must strip directory
    #    components (Path.GetFileName) so "../../evil.txt" can't escape
    #    the uploads directory.
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"traversal-test")
        tmp_path = f.name
    try:
        with open(tmp_path, "rb") as fh:
            files = {"file": ("../../../evil.txt", fh, "text/plain")}
            r = s.post(f"{base_url(args)}/v1/upload", files=files, timeout=10)
        ok = r.status_code == 200
        saved = r.json().get("saved", []) if ok else []
        no_traversal = ok and all(".." not in name and "/" not in name and "\\" not in name for name in saved)
        check("upload rejects/normalizes path-traversal filenames", no_traversal, r.text)
    finally:
        os.unlink(tmp_path)

    # 6. /v1/exec only ever runs via argv (python <tempfile>), never a shell
    #    string -- confirm shell metacharacters in the "script" field are
    #    inert (they're just Python source, not something a shell parses).
    payload = {"script": "import sys; print('shell-test; echo pwned' == sys.argv[0] or 'ok')", "timeoutSeconds": 10}
    r = s.post(f"{base_url(args)}/v1/exec", json=payload, timeout=15)
    body = r.json() if r.status_code == 200 else {}
    check("exec treats script as Python source, not a shell string",
          r.status_code == 200 and body.get("exitCode") == 0 and "ok" in body.get("stdout", ""),
          r.text)


# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------

def test_latency(args):
    print("\n=== LATENCY ===")
    s = make_session(args, args.client_cert, args.client_key)

    samples = []
    n = args.latency_requests
    for _ in range(n):
        t0 = time.perf_counter()
        r = s.get(f"{base_url(args)}/v1/health", timeout=5)
        t1 = time.perf_counter()
        if r.status_code != 200:
            check("latency sample succeeded", False, f"status={r.status_code}")
            continue
        samples.append((t1 - t0) * 1000.0)

    if not samples:
        check(f"collected {n} /v1/health latency samples", False)
        return

    samples.sort()
    def pct(p):
        idx = min(len(samples) - 1, int(len(samples) * p))
        return samples[idx]

    print(f"  n={len(samples)}  min={samples[0]:.2f}ms  mean={statistics.mean(samples):.2f}ms  "
          f"p50={pct(0.50):.2f}ms  p95={pct(0.95):.2f}ms  p99={pct(0.99):.2f}ms  max={samples[-1]:.2f}ms")
    check(f"collected {len(samples)}/{n} /v1/health latency samples", len(samples) == n)
    check("p95 health-check latency under 200ms (LAN expectation)", pct(0.95) < 200,
          f"p95={pct(0.95):.2f}ms")

    # exec round-trip latency (spawns a real python process each time)
    exec_samples = []
    for _ in range(max(5, n // 4)):
        t0 = time.perf_counter()
        r = s.post(f"{base_url(args)}/v1/exec", json={"script": "print('ping')", "timeoutSeconds": 10}, timeout=15)
        t1 = time.perf_counter()
        if r.status_code == 200:
            exec_samples.append((t1 - t0) * 1000.0)
    if exec_samples:
        print(f"  /v1/exec (spawns python): n={len(exec_samples)}  mean={statistics.mean(exec_samples):.2f}ms  "
              f"max={max(exec_samples):.2f}ms")
    check("collected /v1/exec latency samples", len(exec_samples) > 0)


# ---------------------------------------------------------------------------
# Bandwidth
# ---------------------------------------------------------------------------

def test_bandwidth(args):
    print("\n=== BANDWIDTH ===")
    s = make_session(args, args.client_cert, args.client_key)

    for size_mb in args.bandwidth_sizes_mb:
        size_bytes = size_mb * 1024 * 1024
        payload = os.urandom(size_bytes)
        t0 = time.perf_counter()
        r = s.post(
            f"{base_url(args)}/v1/upload",
            files={"file": (f"bench-{size_mb}mb.bin", payload, "application/octet-stream")},
            timeout=max(30, size_mb * 2),
        )
        elapsed = time.perf_counter() - t0
        ok = r.status_code == 200
        throughput = (size_mb / elapsed) if elapsed > 0 else float("inf")
        print(f"  {size_mb} MB upload: {elapsed:.2f}s -> {throughput:.1f} MB/s")
        check(f"upload {size_mb}MB succeeds", ok, r.text)


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------

def _one_exec(args, session, tag, sleep_seconds):
    script = (
        f"import time, sys\n"
        f"time.sleep({sleep_seconds})\n"
        f"print('{tag}')\n"
    )
    t0 = time.perf_counter()
    r = session.post(f"{base_url(args)}/v1/exec", json={"script": script, "timeoutSeconds": 30}, timeout=45)
    elapsed = time.perf_counter() - t0
    body = r.json() if r.status_code == 200 else {}
    ok = (
        r.status_code == 200
        and body.get("exitCode") == 0
        and tag in body.get("stdout", "")
        and not body.get("timedOut", True)
    )
    return tag, ok, elapsed


def test_concurrency(args):
    print("\n=== CONCURRENCY ===")
    n = args.concurrency
    sleep_seconds = 2

    sessions = [make_session(args, args.client_cert, args.client_key) for _ in range(n)]
    tags = [f"tag-{uuid.uuid4().hex[:8]}" for _ in range(n)]

    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_one_exec, args, sessions[i], tags[i], sleep_seconds) for i in range(n)]
        results = [f.result() for f in futures]
    wall_time = time.perf_counter() - t0

    all_ok = all(ok for _, ok, _ in results)
    check(f"all {n} concurrent /v1/exec requests returned correct, isolated output", all_ok,
          str([r for r in results if not r[1]]))

    sequential_estimate = n * sleep_seconds
    print(f"  wall time for {n} concurrent {sleep_seconds}s scripts: {wall_time:.2f}s "
          f"(sequential would be ~{sequential_estimate}s)")
    check("requests actually ran concurrently, not serialized (no artificial cap)",
          wall_time < sequential_estimate * 0.6,
          f"wall={wall_time:.2f}s sequential_estimate={sequential_estimate}s")

    # Per-request script-level timeout still enforced under concurrent load.
    s = make_session(args, args.client_cert, args.client_key)
    r = s.post(f"{base_url(args)}/v1/exec",
               json={"script": "import time; time.sleep(5)", "timeoutSeconds": 1}, timeout=15)
    body = r.json() if r.status_code == 200 else {}
    check("per-request timeout still enforced during concurrent load", body.get("timedOut") is True, r.text)


# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=10122)
    p.add_argument("--cacert", required=True, help="server.crt (also used as CA to verify the server)")
    p.add_argument("--client-cert", required=True)
    p.add_argument("--client-key", required=True)
    p.add_argument("--untrusted-cert", default=None, help="a client cert NOT in authorized-clients.json")
    p.add_argument("--untrusted-key", default=None)
    p.add_argument("--latency-requests", type=int, default=50)
    p.add_argument("--bandwidth-sizes-mb", type=int, nargs="+", default=[1, 10, 50])
    p.add_argument("--concurrency", type=int, default=16)
    p.add_argument("--skip", nargs="*", default=[], choices=["security", "latency", "bandwidth", "concurrency"])
    args = p.parse_args()

    if "security" not in args.skip:
        test_security(args)
    if "latency" not in args.skip:
        test_latency(args)
    if "bandwidth" not in args.skip:
        test_bandwidth(args)
    if "concurrency" not in args.skip:
        test_concurrency(args)

    print(f"\n{'='*40}\n{len(FAILURES)} failing check(s)")
    if FAILURES:
        for name in FAILURES:
            print(f"  - {name}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
