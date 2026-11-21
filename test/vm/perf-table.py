#!/usr/bin/env python3
# 使い方: perf-table.py  test/perf の結果を、条件ごとの中央値と最小・最大の表にする
import json, os, re, statistics as st
import sys
d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "../perf")
cfgs = ["none", "0", "6", "7", "8"]
def runs(c, kind):
    v = []
    for r in range(1, 50):
        p = f"{d}/{c}-r{r}-{kind}"
        if not os.path.exists(p): break
        v.append(p)
    return v
def fmt(x, nd=2):
    return f"{st.median(x):.{nd}f} ({min(x):.{nd}f}-{max(x):.{nd}f})" if x else "-"
print("cfg | send Gbps | vm cpu% | recv Gbps | vm cpu% | conn/s | conn p50 us | conn p99 us | ping avg ms")
for c in cfgs:
    row = [c]
    for k in ("send.json", "recv.json"):
        g, cpu = [], []
        for p in runs(c, k):
            try:
                e = json.load(open(p))["end"]
                g.append(e["sum_received"]["bits_per_second"] / 1e9)
                cpu.append(e["cpu_utilization_percent"]["remote_total"])
            except Exception as ex:
                print("bad", p, ex)
        row += [fmt(g), fmt(cpu, 1)]
    cs = [json.load(open(p)) for p in runs(c, "conn.json")]
    row += [fmt([x["per_sec"] for x in cs], 0), fmt([x["p50_us"] for x in cs], 1), fmt([x["p99_us"] for x in cs], 1)]
    pg = [float(re.search(r"= [\d.]+/([\d.]+)/", open(p).read()).group(1)) for p in runs(c, "ping.txt")]
    row.append(fmt(pg, 3))
    print(" | ".join(row))
