#!/bin/sh
# 比較用の Windows 11 評価版の仮想マシン。画面は VNC 127.0.0.1:5905、試験の線は aodtap2
cd "$(dirname "$0")"
exec sg kvm -c "qemu-system-x86_64 -enable-kvm -machine q35 -cpu host -smp 4 -m 8G \
 -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
 -drive if=pflash,format=raw,file=win-vars.fd \
 -device ahci,id=ahci -drive id=d0,file=win.qcow2,if=none -device ide-hd,drive=d0,bus=ahci.0 \
 -netdev user,id=n0,restrict=on -device e1000,netdev=n0,mac=52:54:00:a0:d0:1a \
 -netdev tap,id=n1,ifname=aodtap2,script=no,downscript=no -device e1000,netdev=n1,mac=52:54:00:a0:d0:0a \
 -usb -device usb-tablet -vga std -display none -vnc 127.0.0.1:5 \
 -rtc base=localtime -monitor unix:win-mon.sock,server,nowait \
 -pidfile win.pid -daemonize"
