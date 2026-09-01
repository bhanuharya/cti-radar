#!/usr/bin/env python3
"""Compare Python vs Rust CTI Radar benchmark results (medians + ratios).

Reads the wall/rss/cpu text files produced by bench.sh and prints a side-by-side
comparison. Rust > 1.0x = faster/lighter; < 1.0x = slower/heavier.

Usage: python3 bench/compare.py <results_dir>
"""
import os
import sys
import statistics


def load(path):
    with open(path) as f:
        return [float(x) for x in f.read().split() if x.strip()]


def median(v):
    return statistics.median(v) if v else 0.0


def main(results_dir):
    labels = ["python", "rust"]
    metrics = ["wall", "rss", "cpu"]
    # files are <label>-<metric>.txt (api) or <label>-scan-wall.txt (scan)
    print(f"{'metric':<10} {'python':>14} {'rust':>14} {'rust/py':>10}  (rust faster/lighter if <1)")
    print("-" * 70)
    for metric in metrics:
        py_path = os.path.join(results_dir, f"python-{metric}.txt")
        rs_path = os.path.join(results_dir, f"rust-{metric}.txt")
        if os.path.exists(py_path) and os.path.exists(rs_path):
            py = median(load(py_path))
            rs = median(load(rs_path))
            ratio = rs / py if py else float("inf")
            print(f"{metric:<10} {py:>14.2f} {rs:>14.2f} {ratio:>10.2f}x")
        else:
            print(f"{metric:<10}  (missing — {py_path} or {rs_path})")

    # scan wall-clock (separate file naming)
    for label in labels:
        p = os.path.join(results_dir, f"{label}-scan-wall.txt")
        if os.path.exists(p):
            v = median(load(p))
            print(f"scan-wall   {label:<6} {v:>8.2f}s")
    print("-" * 70)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
