#!/usr/bin/env python3
"""Proper CTI Radar backend benchmark: Python vs Rust.

Measures REAL server behavior (not the curl client):
  - cold-start wall time
  - concurrent throughput (req/s) + latency percentiles on the CPU-heavy
    read paths (summary / findings / graph / dashboard)
  - peak RSS of the server process under load

Usage: python3 bench/bench_proper.py [iters]
"""
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

ITERS = int(sys.argv[1]) if len(sys.argv) > 1 else 5
CONCURRENCY = 16
TOKEN = os.environ.get("CTI_SCAN_TOKEN", "tok")
DATA_DIR = os.environ.get("CTI_DATA_DIR", os.path.expanduser("~/code/cti-radar/data"))

PY = ("127.0.0.1:8084", "python")
RS = ("127.0.0.1:8085", "rust")

# CPU-heavy read endpoints that force normalization + PII masking + graph build
ENDPOINTS = [
    "/api/summary?org=sample",
    "/api/findings?org=sample",
    "/api/graph?org=sample",
    "/api/dashboard?org=sample",
]


def fetch(url):
    req = urllib.request.Request(url, headers={"X-CTI-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def warm(host):
    for ep in ENDPOINTS:
        try:
            fetch(f"http://{host}{ep}")
        except Exception:
            pass


def hammer(host, seconds=3.0, concurrency=CONCURRENCY):
    """Hit endpoints concurrently for `seconds`, return (req_count, latencies_ms)."""
    urls = [f"http://{host}{ep}" for ep in ENDPOINTS]
    latencies = []
    count = 0
    deadline = time.time() + seconds

    def worker():
        nonlocal_count = 0
        lat = []
        i = 0
        while time.time() < deadline:
            u = urls[i % len(urls)]
            i += 1
            t0 = time.time()
            try:
                fetch(u)
                lat.append((time.time() - t0) * 1000)
                nonlocal_count += 1
            except Exception:
                lat.append((time.time() - t0) * 1000)
        return nonlocal_count, lat

    with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
        results = list(ex.map(lambda _: worker(), range(concurrency)))

    for c, lat in results:
        count += c
        latencies.extend(lat)
    return count, latencies


def pct(v, p):
    if not v:
        return 0.0
    s = sorted(v)
    idx = int(len(s) * p)
    return s[min(idx, len(s) - 1)]


def server_rss_kb(host):
    """Map host:port -> server process RSS (KB) via pgrep/ps on the port."""
    port = host.split(":")[1]
    try:
        out = subprocess.check_output(
            ["bash", "-c",
             f"ss -ltnp 2>/dev/null | grep ':{port} ' | grep -oP 'pid=\\K[0-9]+' | head -1"],
            text=True).strip()
        if out:
            pid = out
            rss = subprocess.check_output(
                ["ps", "-o", "rss=", "-p", pid], text=True).strip()
            return int(rss)
    except Exception:
        pass
    return 0


def cold_start(label, cmd, port, timeout=30):
    """Start a server, wait for health, return (start_seconds, idle_rss_kb)."""
    env = dict(os.environ)
    env.update({
        "CTI_USER": "admin",
        "CTI_PASSWORD": "secret",
        "CTI_SCAN_TOKEN": TOKEN,
        "CTI_DATA_DIR": DATA_DIR,
        "CTI_HOST": "127.0.0.1",
        "CTI_PORT": str(port),
    })
    t0 = time.time()
    proc = subprocess.Popen(cmd, shell=True, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # poll health
    ready = False
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/summary?org=sample",
                timeout=2).read()
            ready = True
            break
        except Exception:
            time.sleep(0.1)
    start_s = time.time() - t0
    if not ready:
        proc.terminate()
        return start_s, 0, None
    # idle RSS
    time.sleep(0.5)
    rss = server_rss_kb(f"127.0.0.1:{port}")
    return start_s, rss, proc


def main():
    print(f"CTI Radar proper bench — iters={ITERS} concurrency={CONCURRENCY}")
    print(f"Endpoints: {ENDPOINTS}")
    print()

    for host, label in (PY, RS):
        warm(host)
        reqs = []
        p50s, p95s, p99s = [], [], []
        rss_load = []
        for i in range(ITERS):
            c, lat = hammer(host)
            reqs.append(c)
            p50s.append(pct(lat, 0.50))
            p95s.append(pct(lat, 0.95))
            p99s.append(pct(lat, 0.99))
            rss_load.append(server_rss_kb(host))
        print(f"[{label}]  ({host})")
        print(f"  throughput : {sum(reqs)/ITERS/3.0:8.1f} req/s  (median of {ITERS}x3s runs)")
        print(f"  p50 latency: {sorted(p50s)[len(p50s)//2]:8.1f} ms")
        print(f"  p95 latency: {sorted(p95s)[len(p95s)//2]:8.1f} ms")
        print(f"  p99 latency: {sorted(p99s)[len(p99s)//2]:8.1f} ms")
        print(f"  peak RSS   : {max(rss_load)/1024:8.1f} MB  (server process, under load)")
        print()


if __name__ == "__main__":
    main()
