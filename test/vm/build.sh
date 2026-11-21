#!/bin/sh
# ソースを仮想マシンへ送り、ビルドして読み込み直す
cd "$(dirname "$0")"
scp -q -i id_vm -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o IdentityAgent=none -o IdentitiesOnly=yes ../../kld/aod.c ../../kld/aod.h ../../kld/Makefile root@127.0.0.1:/root/aod/ || exit 1
./ssh-target.sh 'cd /root/aod && kldunload aod 2>/dev/null; make 2>&1 | grep -A6 "error:\|warning:"; make >/dev/null 2>&1 && kldload ./aod.ko && kldstat | grep aod'
