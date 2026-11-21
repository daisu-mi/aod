#!/bin/sh
# 使い方: perf.sh [回数] [出力先]  性能を測り、出力先(既定は test/perf)に残す
# 条件: none(モジュールなし)、0(読み込んだが切)、6、7、8 を順に回し、これを回数ぶん繰り返す
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
		$ip3 -c 10.99.0.2 -t 10 -J > $p-send.json 2>&1       # ホストから仮想マシンへ
		$ip3 -c 10.99.0.2 -t 10 -J -R > $p-recv.json 2>&1    # 仮想マシンからホストへ
		python3 conn.py 5000 > $p-conn.json 2>&1
		sudo -n ping -q -c 3000 -i 0.002 10.99.0.2 | tail -1 > $p-ping.txt 2>&1
		echo "round $r cfg $c done"
	done
	r=$((r + 1))
done
setcfg 0
./ssh-target.sh 'pkill iperf3; pkill -F /tmp/inetd-perf.pid'
