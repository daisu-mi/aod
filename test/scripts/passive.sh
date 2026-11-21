#!/bin/bash
# Usage: passive.sh N
# With personality N, open three connections from the prober to the target and three back,
# save the packets to test/passive/kindN.pcap, then run p0f and compute JA4T
cd "$(dirname "$0")"
k=$1; out=../passive; pcap=$out/kind$k.pcap
./ssh-target.sh "sysctl -q net.inet.tcp.emu_kind=$k >/dev/null" || exit 1
www=$(mktemp -d); echo ok > $www/x
(cd $www && exec python3 -m http.server 8099 --bind 10.99.0.1 >/dev/null 2>&1) & web=$!
sudo -n timeout 14 tcpdump -q -ni aodtap0 -w $pcap tcp 2>/dev/null & cap=$!
sleep 1
for i in 1 2 3; do (exec 3<>/dev/tcp/10.99.0.2/22; head -c 10 <&3 >/dev/null) 2>/dev/null; done
./ssh-target.sh 'for i in 1 2 3; do fetch -qo /dev/null -T 5 http://10.99.0.1:8099/x; done'
wait $cap; kill $web 2>/dev/null; rm -rf $www
sudo -n chown $(id -u) $pcap
rm -f $out/kind$k-p0f.log
p0f -r $pcap -o $out/kind$k-p0f.log >/dev/null 2>&1
echo "== p0f"
grep "mod=syn" $out/kind$k-p0f.log | grep -o "subj=.*" | sed 's/|raw_sig=.*//; s/|dist=[0-9]*//; s/|params=[a-z]*//' | sort -u
echo "== JA4T"
python3 ja4t.py $pcap | tee $out/kind$k-ja4t.txt
