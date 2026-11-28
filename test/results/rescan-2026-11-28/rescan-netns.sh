#!/bin/sh
# Usage: rescan-netns.sh outdir
# Scans a network namespace on the second Linux guest with Nmap, first unset
# (0) and then set to 8, over IPv4 and IPv6, and the guest itself (0). Beside
# each output it stores the command line and a reading of the settings.
cd "$(dirname "$0")"
out=$1; mkdir -p "$out"
T=./ssh-linux2.sh
$T 'lsmod | grep -q aod_linux || sudo insmod ~/aod-released/linux/aod_linux.ko
sudo ip netns add c1 2>/dev/null
sudo ip link add mv1 link ens4 type macvlan mode bridge 2>/dev/null && sudo ip link set mv1 netns c1
sudo ip netns exec c1 ip link set lo up
sudo ip netns exec c1 ip addr replace 10.99.0.26/30 dev mv1
sudo ip netns exec c1 ip link set mv1 up
sudo test -s /run/sshd-c1.pid || sudo ip netns exec c1 /usr/sbin/sshd -o PidFile=/run/sshd-c1.pid
sleep 3; sudo ip netns exec c1 ip -br addr; sudo ip netns exec c1 ss -ltn' > "$out/setup.txt" 2>&1
{
echo "== date"; date -u
echo "== nmap"; nmap --version | head -1; sha256sum /usr/share/nmap/nmap-os-db
echo "== guest"; $T 'uname -r; sha256sum ~/aod-released/linux/aod_linux.c ~/aod-released/common/aod.h ~/aod-released/linux/aod_linux.ko; lsmod | grep aod'
} > "$out/environment.txt" 2>&1
sudo -n ip link set aodtap3 up; sudo -n ip addr replace 10.99.0.25/30 dev aodtap3
a6c=$($T "sudo ip netns exec c1 ip -6 -o addr show dev mv1 scope link" | awk '{sub(/\/.*/,"",$4);print $4}')
a6h=$($T "ip -6 -o addr show dev ens4 scope link" | awk '{sub(/\/.*/,"",$4);print $4}')
echo "c1 $a6c host $a6h" >> "$out/setup.txt"
rd() { echo "host $($T 'sysctl -n net.ipv4.tcp_emu_kind'), c1 $($T 'sudo ip netns exec c1 sysctl -n net.ipv4.tcp_emu_kind')"; }
scan() { # name addr4 addr6 label n4 n6
  name=$1; a4=$2; a6=$3; k=$4; n4=$5; n6=$6
  i=1; while [ $i -le $n4 ]; do
    { echo "# command: nmap -O -n -Pn -p 22,23 --osscan-guess $a4"; echo "# settings read before the scan: $(rd)"
      sudo -n nmap -O -n -Pn -p 22,23 --osscan-guess $a4; } > "$out/$name-kind$k-run$i-nmap4.txt" 2>&1
    i=$((i+1)); done
  i=1; while [ $i -le $n6 ]; do
    { echo "# command: nmap -6 -O -n -Pn -p 22,23 --osscan-guess $a6%aodtap3"; echo "# settings read before the scan: $(rd)"
      sudo -n nmap -6 -O -n -Pn -p 22,23 --osscan-guess $a6%aodtap3; } > "$out/$name-kind$k-run$i-nmap6.txt" 2>&1
    i=$((i+1)); done
}
$T 'sudo ip netns exec c1 sysctl -w net.ipv4.tcp_emu_kind=0' >> "$out/setup.txt" 2>&1
scan c1 10.99.0.26 $a6c 0 5 5
scan host 10.99.0.22 $a6h 0 5 5
$T 'sudo ip netns exec c1 sysctl -w net.ipv4.tcp_emu_kind=8' >> "$out/setup.txt" 2>&1
scan c1 10.99.0.26 $a6c 8 10 5
scan host 10.99.0.22 $a6h 0with-c1-set 5 5
echo finished >> "$out/setup.txt"
