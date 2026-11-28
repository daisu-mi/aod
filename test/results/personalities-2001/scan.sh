#!/bin/sh
# Five scans of each personality of 2001 (1 to 5) on the FreeBSD test machine.
# The target is on the closed test link only.  ssh-target.sh is the same
# wrapper that test/scripts/scan.sh uses to reach the test machine.
cd "$(dirname "$0")"
for k in 1 2 3 4 5; do
  ./ssh-target.sh "sysctl -q net.inet.tcp.emu_kind=$k >/dev/null" || exit 1
  for i in 1 2 3 4 5; do
    sudo -n nmap -O -n -Pn -p 22,23 --osscan-guess 10.99.0.2 > kind$k-run$i.txt 2>&1
  done
done
./ssh-target.sh "sysctl -q net.inet.tcp.emu_kind=0 >/dev/null"
