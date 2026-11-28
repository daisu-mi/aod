# One personality per jail

The module in `freebsd/` keeps its setting and its hooks per network stack
(vnet). A jail that has its own network stack gets its own
`net.inet.tcp.emu_kind`. The host and each such jail can then answer a scanner
as different systems, on one kernel.

A jail that shares the host's stack is not a separate unit. It looks like the
host and cannot change the setting.

## Example

This is the arrangement used for the measurement. `vtnet1` is the interface
that faces the scanner. Each jail is reached through an `epair` on a bridge.

```
kldload ./aod.ko

ifconfig bridge0 create
ifconfig epair1 create
ifconfig bridge0 addm vtnet1 addm epair1a up
ifconfig epair1a up

jail -c name=j1 path=/ vnet vnet.interface=epair1b host.hostname=j1 persist
jexec j1 ifconfig lo0 inet 127.0.0.1/8 up
jexec j1 ifconfig epair1b inet 10.99.0.14/30 up

jexec j1 sysctl net.inet.tcp.emu_kind=8
jexec j1 sysctl net.inet.tcp.emu_lock=1
```

## The lock

`net.inet.tcp.emu_lock=1` keeps every process inside the jail, root included,
from changing `emu_kind` or clearing the lock. Set it after `emu_kind`.

The lock covers the personality number only. Root inside the jail can still
change other settings of its own network stack. Doing so can break the
match: in one run, a jail set to Windows 11 no longer matched exactly after
such a change (`results/spoiled.txt`).

Unloading the module puts every stack back as it was. Loading it again starts
with every stack at 0.

## Measurement

Nmap 7.98, `-O`, from a prober on the same closed link.

| Target | `emu_kind` | Nmap verdict |
|---|---|---|
| host, 10.99.0.2 | 0 | no exact match (first guess Android 4.0.1 – 4.0.4 (Linux 3.0), 93%; second FreeBSD 12.0-RELEASE – 13.0-RELEASE, 92%; so in `results/scan1-10.99.0.2.txt` and in all ten scans of `results/ten-scans/`. In `results/scan3-10.99.0.2.txt` FreeBSD 12.0-RELEASE – 13.0-RELEASE is first, 95%) |
| jail, 10.99.0.14 | 8 | exact: Microsoft Windows 10 1703 or Windows 11 21H2 |
| jail, 10.99.0.18 | 6 | exact: Linux 4.15 – 5.19, with OpenWrt 21.02 and MikroTik RouterOS 7 (both Linux-based) also listed |

- Changing the host to 6 did not change the value or the verdict of either jail.
- Under scanning, 40 rounds of load and unload and 30 rounds of creating and
  removing a jail all succeeded.
- After unloading, the changed kernel variable was back to its old value in
  all three stacks, and no packet was dropped for a bad checksum.

The three addresses were later scanned ten times each
(`results/ten-scans/`). The host had no exact match in any scan. The Windows
jail was an exact match for Microsoft Windows 10 1703 or Windows 11 21H2 in
all ten. For the Linux jail, Linux 4.15 – 5.19 was listed first in all ten;
nine also listed OpenWrt 21.02, MikroTik RouterOS 7, or both.

`results/` holds the raw Nmap output.
