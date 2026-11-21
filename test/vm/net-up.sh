#!/bin/sh
# 試験用の閉じた線。ホストと仮想マシンだけがつながる(ホストは転送しない)
sudo ip tuntap add dev aodtap0 mode tap user "$USER" 2>/dev/null
sudo ip addr replace 10.99.0.1/30 dev aodtap0
sudo ip link set aodtap0 up
