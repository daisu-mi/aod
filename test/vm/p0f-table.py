#!/usr/bin/env python3
"""p0f の記録から、仮想マシン(10.99.0.2)とホスト(10.99.0.1)の判定を取り出す。
使い方: p0f-table.py test/passive/kind*-p0f.log
"""
import re, sys
for path in sys.argv[1:]:
    kind = re.search(r"kind(\d+)", path).group(1)
    rows = set()
    for line in open(path):
        if "mod=syn" not in line: continue
        f = dict(x.split("=", 1) for x in line.strip().split("] ", 1)[1].split("|") if "=" in x)
        who = f[f["subj"]].split("/")[0]
        role = "出す SYN" if f["mod"] == "syn" else "返す SYN/ACK"
        rows.add((who, role, f.get("os", ""), f.get("raw_sig", "")))
    for r in sorted(rows):
        print(f"kind {kind} | {r[0]} | {r[1]} | {r[2]} | {r[3]}")
