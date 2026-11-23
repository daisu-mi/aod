# Measurements

`results/` holds the raw Nmap output behind the tables in the README and in the
paper: one set per personality (`kind0`, `kind6`, `kind7`, `kind8`) and one for
each real host used for comparison (Ubuntu 26.04.1, Windows 11 build 22621).
Files ending in `-fp.txt` include the full fingerprint.
`linux-host-kind8-nmap.txt` is the Linux module on an Ubuntu host. The results
for jails and containers are in `freebsd/jail/results/` and
`linux/lxc/results/`.

`scripts/` holds the scripts that produced them. They are a record of the
method, not a portable test suite: they assume a prober at 10.99.0.1, the
FreeBSD target at 10.99.0.2 on a link that is not forwarded anywhere, and a
helper `ssh-target.sh` that runs a command on the target as root. Adapt those
before use, and scan only hosts you operate.

| Script | What it does |
|---|---|
| `scan.sh N` | select personality N, run `nmap -O` |
| `portscan.sh N` | SYN, connect, ACK, FIN, NULL, Xmas, window and Maimon scans |
| `passive.sh N` | capture one connection in each direction, run p0f, compute JA4T |
| `ja4t.py` | compute JA4T and JA4TS strings from a capture (uses tshark) |
| `p0f-table.py` | summarize p0f logs |
| `perf.sh`, `conn.py`, `perf-table.py` | throughput, connection rate and ping; print medians |
