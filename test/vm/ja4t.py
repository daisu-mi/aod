#!/usr/bin/env python3
"""pcap から SYN と SYN/ACK を取り出し、JA4T / JA4TS の形で出す。

形は FoxIO の JA4T と同じ: ウィンドウ_オプション番号の並び_MSS_スケール
使い方: ja4t.py ファイル.pcap
"""
import subprocess, sys

def kinds(hexstr):
    b = bytes.fromhex(hexstr.replace(":", "")) if hexstr else b""
    out, i = [], 0
    while i < len(b):
        k = b[i]; out.append(str(k))
        if k == 0: break
        if k == 1: i += 1; continue
        if i + 1 >= len(b) or b[i+1] < 2: break
        i += b[i+1]
    return "-".join(out) if out else "00"

# tshark は保護機能(AppArmor)でこの場所を直接開けないので、標準入力から渡す
cmd = ["tshark", "-r", "-", "-Y", "tcp.flags.syn==1", "-T", "fields", "-E", "separator=|",
       "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "tcp.flags.ack", "-e", "ip.ttl",
       "-e", "tcp.window_size_value", "-e", "tcp.options", "-e", "tcp.options.mss_val",
       "-e", "tcp.options.wscale.shift"]
seen = set()
for line in subprocess.run(cmd, stdin=open(sys.argv[1], "rb"), capture_output=True).stdout.decode().splitlines():
    src, dst, dport, ack, ttl, win, opts, mss, ws = (line.split("|") + [""] * 9)[:9]
    is_ack = ack in ("1", "True")
    fp = f"{win}_{kinds(opts)}_{mss or '00'}_{ws or '00'}"
    row = (src, "JA4TS" if is_ack else "JA4T", fp, ttl)
    if row not in seen:
        seen.add(row)
        print(f"{src:12} {row[1]:5} {fp:40} ttl={ttl}")
