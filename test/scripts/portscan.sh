#!/bin/sh
# Usage: portscan.sh N   select personality N, then run each Nmap port scan type
# Port 22 is open and 23 is closed. Output goes to test/results/kindN-portscan.txt
cd "$(dirname "$0")"
k=$1; out=../results/kind$k-portscan.txt; : > $out
./ssh-target.sh "sysctl -q net.inet.tcp.emu_kind=$k >/dev/null" || exit 1
for t in sS sT sA sF sN sX sW sM; do
	r=$(sudo -n nmap -$t -n -Pn -p 22,23 --reason 10.99.0.2 2>&1 | tee -a $out | grep "^2[23]/tcp" | awk '{print $1, $2, "(" $4, $5, $6 ")"}' | tr '\n' ' ')
	echo "-$t  $r"
done
