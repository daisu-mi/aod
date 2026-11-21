#!/bin/sh
# Usage: scan.sh N   select personality N, run nmap -O, save the output in test/results
cd "$(dirname "$0")"
k=$1; out=../results/kind$k-nmap.txt
./ssh-target.sh "sysctl -q net.inet.tcp.emu_kind=$k >/dev/null" || exit 1
sudo -n nmap -O -n -Pn -p 22,23 --osscan-guess 10.99.0.2 > $out 2>&1
grep "^OS details\|^Running\|^Aggressive OS guesses\|^No exact" $out | cut -c1-230
tr -d '\n' < $out | sed 's/OS://g' | grep -o "[A-Z0-9]*([^)]*)" | grep -v "^SCAN" | awk '!s[substr($0,1,3)]++'
