#!/usr/bin/env python3
# 使い方: conn.py 回数  10.99.0.2 の 9 番へ順につないで切り、かかった時間を JSON で出す
import json, socket, struct, sys, time

n = int(sys.argv[1])
lat = []
t0 = time.perf_counter()
for _ in range(n):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    a = time.perf_counter()
    s.connect(("10.99.0.2", 9))
    lat.append(time.perf_counter() - a)
    s.close()
el = time.perf_counter() - t0
lat.sort()
us = lambda x: round(x * 1e6, 1)
print(json.dumps({"n": n, "per_sec": round(n / el, 1), "p50_us": us(lat[n // 2]),
                  "p99_us": us(lat[n * 99 // 100])}))
