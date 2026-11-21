#!/bin/sh
# 比較用の Linux 仮想マシンの線。ホスト 10.99.0.5、仮想マシン 10.99.0.6(ホストは転送しない)
sudo ip tuntap add dev aodtap1 mode tap user "$USER" 2>/dev/null
sudo ip addr replace 10.99.0.5/30 dev aodtap1
sudo ip link set aodtap1 up
