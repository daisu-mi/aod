#!/bin/sh
# 使い方: portscan.sh 番号  その設定に切り替え、nmap の各種ポートスキャンを当てる
# 22 は開いたポート、23 は閉じたポート。結果は test/results/kindN-portscan.txt に残す
cd "$(dirname "$0")"
k=$1; out=../results/kind$k-portscan.txt; : > $out
./ssh-target.sh "sysctl -q net.inet.tcp.emu_kind=$k >/dev/null" || exit 1
for t in sS sT sA sF sN sX sW sM; do
	r=$(sudo -n nmap -$t -n -Pn -p 22,23 --reason 10.99.0.2 2>&1 | tee -a $out | grep "^2[23]/tcp" | awk '{print $1, $2, "(" $4, $5, $6 ")"}' | tr '\n' ' ')
	echo "-$t  $r"
done
