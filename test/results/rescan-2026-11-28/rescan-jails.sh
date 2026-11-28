#!/bin/sh
# Usage: rescan-jails.sh outdir
# Scans two vnet jails on the FreeBSD guest with Nmap, first unset (0) and then
# set (j1: 8, j2: 6), over IPv4 and IPv6. Beside each output it stores the
# command line and a reading of the settings taken just before the scan.
cd "$(dirname "$0")"
out=$1; mkdir -p "$out"
T=./ssh-target.sh
{
echo "== date"; date -u
echo "== nmap"; nmap --version | head -1; sha256sum /usr/share/nmap/nmap-os-db
echo "== guest"; $T 'uname -r; sha256 /root/aod/aod.c /root/aod/aod.h /root/aod/aod.ko; kldstat | grep aod'
} > "$out/environment.txt" 2>&1

$T 'ifconfig bridge0 >/dev/null 2>&1 || ifconfig bridge0 create
for n in 1 2; do ifconfig epair${n}a >/dev/null 2>&1 || ifconfig epair$n create; done
ifconfig bridge0 addm vtnet1 addm epair1a addm epair2a up 2>/dev/null; ifconfig epair1a up; ifconfig epair2a up
jls -j j1 >/dev/null 2>&1 || jail -c name=j1 path=/ vnet vnet.interface=epair1b host.hostname=j1 persist
jls -j j2 >/dev/null 2>&1 || jail -c name=j2 path=/ vnet vnet.interface=epair2b host.hostname=j2 persist
jexec j1 ifconfig lo0 inet 127.0.0.1/8 up; jexec j1 ifconfig epair1b inet 10.99.0.14/30 up; jexec j1 ifconfig epair1b inet6 auto_linklocal -ifdisabled up
jexec j2 ifconfig lo0 inet 127.0.0.1/8 up; jexec j2 ifconfig epair2b inet 10.99.0.18/30 up; jexec j2 ifconfig epair2b inet6 auto_linklocal -ifdisabled up
for j in j1 j2; do jexec $j sh -c "pgrep -q sshd || /usr/sbin/sshd -o PidFile=/var/run/sshd-$j.pid"; done; sleep 3' > "$out/setup.txt" 2>&1
sudo -n ip addr replace 10.99.0.13/30 dev aodtap0; sudo -n ip addr replace 10.99.0.17/30 dev aodtap0
a6_1=$($T "jexec j1 ifconfig epair1b" | awk '/inet6 fe80/{sub(/%.*/,"",$2);print $2}')
a6_2=$($T "jexec j2 ifconfig epair2b" | awk '/inet6 fe80/{sub(/%.*/,"",$2);print $2}')
echo "j1 $a6_1  j2 $a6_2" >> "$out/setup.txt"

scan() { # name jail addr4 addr6 kind n4 n6
  name=$1; j=$2; a4=$3; a6=$4; k=$5; n4=$6; n6=$7
  $T "jexec $j sysctl net.inet.tcp.emu_lock=0 >/dev/null 2>&1; jexec $j sysctl net.inet.tcp.emu_kind=$k" >> "$out/setup.txt" 2>&1
  i=1; while [ $i -le $n4 ]; do
    f="$out/$name-kind$k-run$i-nmap4.txt"
    { echo "# command: nmap -O -n -Pn -p 22,23 --osscan-guess $a4"
      echo "# settings read before the scan: host $($T 'sysctl -n net.inet.tcp.emu_kind'), $j $($T "jexec $j sysctl -n net.inet.tcp.emu_kind")"
      sudo -n nmap -O -n -Pn -p 22,23 --osscan-guess $a4; } > "$f" 2>&1
    i=$((i+1)); done
  i=1; while [ $i -le $n6 ]; do
    f="$out/$name-kind$k-run$i-nmap6.txt"
    { echo "# command: nmap -6 -O -n -Pn -p 22,23 --osscan-guess $a6%aodtap0"
      echo "# settings read before the scan: host $($T 'sysctl -n net.inet.tcp.emu_kind'), $j $($T "jexec $j sysctl -n net.inet.tcp.emu_kind")"
      sudo -n nmap -6 -O -n -Pn -p 22,23 --osscan-guess $a6%aodtap0; } > "$f" 2>&1
    i=$((i+1)); done
}
scan j1 j1 10.99.0.14 $a6_1 0 5 5
scan j2 j2 10.99.0.18 $a6_2 0 5 5
scan j1 j1 10.99.0.14 $a6_1 8 10 5
scan j2 j2 10.99.0.18 $a6_2 6 10 5
echo finished >> "$out/setup.txt"
