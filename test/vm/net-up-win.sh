#!/bin/sh
# 比較用の Windows 仮想マシンの線。ホスト 10.99.0.9、仮想マシン 10.99.0.10(ホストは転送しない)
sudo ip tuntap add dev aodtap2 mode tap user "$USER" 2>/dev/null
sudo ip addr replace 10.99.0.9/30 dev aodtap2
sudo ip link set aodtap2 up
