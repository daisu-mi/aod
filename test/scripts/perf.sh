#!/bin/sh
# Usage: perf.sh [rounds] [outdir]   measure performance; results go to outdir (default test/perf)
# Conditions: none (module unloaded), 0 (loaded, off), 6, 7, 8, run in turn; the whole cycle repeats
cd "$(dirname "$0")"
rounds=${1:-5}
out=${2:-../perf}; mkdir -p $out
ip3=iperf3

./ssh-target.sh 'pkill iperf3; pkill -F /tmp/inetd-perf.pid 2>/dev/null
  echo "discard stream tcp nowait root internal" > /tmp/inetd-perf.conf
  inetd -R 0 -s 0 -c 0 -p /tmp/inetd-perf.pid /tmp/inetd-perf.conf
  daemon -f iperf3 -s -B 10.99.0.2; sleep 1'

setcfg() {
	if [ "$1" = none ]; then
		./ssh-target.sh 'kldunload aod 2>/dev/null; true'
	else
		./ssh-target.sh "kldstat -q -n aod.ko || kldload /root/aod/aod.ko; sysctl -q net.inet.tcp.emu_kind=$1 >/dev/null"
	fi
}

r=1
while [ $r -le $rounds ]; do
	for c in none 0 6 7 8; do
		setcfg $c
		p=$out/$c-r$r
		$ip3 -c 10.99.0.2 -t 10 -J > $p-send.json 2>&1       # prober to target
		$ip3 -c 10.99.0.2 -t 10 -J -R > $p-recv.json 2>&1    # target to prober
		python3 conn.py 5000 > $p-conn.json 2>&1
		sudo -n ping -q -c 3000 -i 0.002 10.99.0.2 | tail -1 > $p-ping.txt 2>&1
		echo "round $r cfg $c done"
	done
	r=$((r + 1))
done
setcfg 0
./ssh-target.sh 'pkill iperf3; pkill -F /tmp/inetd-perf.pid'
