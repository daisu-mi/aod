# Rescans of 28 November 2026

Scans of two FreeBSD jails and of a Linux network namespace, made with the
modules built from the sources in this repository (`freebsd/aod.c`,
`linux/aod_linux.c`, `common/aod.h`; their checksums are in each
`environment.txt`). Earlier series were made with earlier builds and without
a scan of the same target before its setting.

Each output file starts with two comment lines: the Nmap command, and the
settings read on the target machine just before the scan.

| Directory | Target | Setting | Scans |
|---|---|---|---|
| `freebsd-jail/` | jail `j1`, 10.99.0.14 | 0, then 8 | 0: 5 IPv4, 5 IPv6; 8: 10 IPv4, 5 IPv6 |
| `freebsd-jail/` | jail `j2`, 10.99.0.18 | 0, then 6 | 0: 5 IPv4, 5 IPv6; 6: 10 IPv4, 5 IPv6 |
| `linux-netns/` | namespace `c1`, 10.99.0.26 | 0, then 8 | 0: 5 IPv4, 5 IPv6; 8: 10 IPv4, 5 IPv6 |
| `linux-netns/` | its host, 10.99.0.22 | 0 | 5 IPv4 and 5 IPv6, before and after the namespace was set |

The host of the jails was at setting 7 throughout and was not scanned. The
namespace reaches the link through a macvlan interface on the guest's test
interface. The LXC container of `linux/lxc/` was not scanned again.

A first attempt at the namespace scans had no listening port inside the
namespace and is not kept here.

`rescan-jails.sh` and `rescan-netns.sh` are the scripts that made the scans.
They assume the author's two virtual machines and their helper scripts.
