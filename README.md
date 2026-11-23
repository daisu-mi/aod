# aod — Anti OS Detection

A kernel module that makes a host answer OS fingerprinting tools as if it ran a
different operating system. There is one for FreeBSD and one for Linux.

The first version was a modified FreeBSD 4.3 kernel, described in a 2001 paper.
This repository holds a rewrite for FreeBSD 15.1 as a loadable module, and a
version for Linux built from the same personality table. The patch and source
tree of the old version were recovered later and are kept in `legacy/`.

| Directory | Contents |
|---|---|
| `freebsd/` | The module for FreeBSD 15.1 (`pfil(9)` hooks, no change to the kernel source) |
| `freebsd/jail/` | Giving each jail its own personality |
| `linux/` | The module for Linux (netfilter hooks; written against Linux 7.0) |
| `linux/lxc/` | Giving each container its own personality |
| `common/` | The personality definitions shared by both modules |
| `test/` | The scripts used for the measurements (`scripts/`) and the raw Nmap output (`results/`) |
| `legacy/` | The 2001 patch for FreeBSD 4.3, its source tree, and the WIT2001 paper and slides |

## What it does

The tables in this section were measured with the FreeBSD module on the host.

With the module loaded and a personality selected, the tools report:

| `net.inet.tcp.emu_kind` | Personality | Nmap 7.98 `-O` | p0f 3.09b (outbound SYN) |
|---|---|---|---|
| 0 | off | no exact match (guesses FreeBSD 12–13) | FreeBSD |
| 6 | Linux, as in the Nmap database | exact: Linux 4.15 – 5.19, usually with other Linux-based entries (see below) | Linux 2.2.x-3.x |
| 7 | Linux, as measured on Ubuntu 26.04.1 | no exact match; best guess Linux 4.15 – 5.19 (97%) | Linux 2.2.x-3.x |
| 8 | Windows 11 | exact: Microsoft Windows 10 1703 or Windows 11 21H2 | Windows NT kernel |

Each personality was compared with a real host on the same test network:

- **Windows 11** (build 22621). Nmap, p0f and JA4T give personality 8 and the
  real host the same result. In the Nmap fingerprints every test line from OPS
  to IE is identical; the SEQ line differs only in two measured values that
  also vary between runs of the same host.
- **Ubuntu 26.04.1** (Linux 7.0). Nmap does not recognize the real host: its
  database ends at Linux 6.0. Personality 7 gets the same non-match, with the
  same list of guesses. Personality 6 follows the database instead and is an
  exact match. Pick 6 to satisfy the tool, 7 to look like a current machine.
  With 6, Nmap lists every database entry the fingerprint satisfies. Linux
  4.15 – 5.19 is always first. In most runs OpenWrt 21.02 (Linux 5.4) follows,
  and often MikroTik RouterOS 7.2 – 7.5 (Linux 5.6.3) as well; both are Linux
  systems. The fingerprints of these runs differ only in two measured values
  of the SEQ line. `test/results/kind6-rerun/` holds six such runs.

With personality 8, FIN, NULL and Xmas scans show every port as closed, as they
do against Windows. SYN and connect scans show the true state with every
personality.

Values 1 to 5 are the personalities of the 2001 version (FreeBSD, NetBSD,
Windows, Windows 2000, Cisco). They are kept for reference and do not match
anything in a current Nmap database: those systems generated initial sequence
numbers in recognizable ways, and this module does not change sequence numbers.

## Build and use

On FreeBSD 15.1 with the kernel sources in `/usr/src`:

```
cd freebsd
make
kldload ./aod.ko
sysctl net.inet.tcp.emu_kind=8
```

To stop: `sysctl net.inet.tcp.emu_kind=0`, then `kldunload aod`.

While a personality is active the module turns off per-connection TCP timestamp
offsets (`net.inet.tcp.ts_offset_per_conn`). The previous value is restored
when the personality is switched off or the module is unloaded.

The setting is kept per network stack. A jail with its own stack can have a
personality of its own, and can be kept from changing it; see
[`freebsd/jail/`](freebsd/jail/).

### Linux

With the kernel headers installed:

```
cd linux
make
insmod ./aod_linux.ko
sysctl -w net.ipv4.tcp_emu_kind=8
```

To stop: `sysctl -w net.ipv4.tcp_emu_kind=0`, then `rmmod aod_linux`.

While a personality is active the module changes `tcp_timestamps` and
`tcp_ecn` of the namespace, and puts them back afterwards. The setting is kept
per network namespace; see [`linux/lxc/`](linux/lxc/) for containers.

The Linux module was tested with personality 8 only. On an Ubuntu 26.04.1
host (Linux 7.0) and in a container on it, Nmap 7.98 reports an exact match:
Microsoft Windows 10 1703 or Windows 11 21H2. The other numbers in "What it
does" and "Cost" were not measured with it.

## How it works

Two hooks are registered on the IPv4 `pfil` head of each network stack (on
Linux, two netfilter hooks in each network namespace). The module keeps no
per-connection state.

- Outbound: TTL, DF, IP ID, the window of SYN and SYN/ACK, the order of TCP
  options, the timestamp option of the host's own SYN, the window scale value,
  the acknowledgment field of a bare RST, the code of an ICMP echo reply.
- Inbound: clears the ECN bits of a SYN, and answers by itself the segments
  that the imitated system treats differently (no flags, SYN+FIN, FIN without
  ACK).

## Cost

Measured in a QEMU/KVM guest (8 vCPU) against the host over a virtual link;
medians of five rounds. Differences below about ten percent are not resolved by
this setup.

| Condition | receive Gbit/s | send Gbit/s | connections/s |
|---|---|---|---|
| no module | 2.50 | 16.64 | 14828 |
| loaded, off | 2.53 | 16.01 | 14483 |
| 6 Linux (database) | 2.49 | 16.03 | 16537 |
| 7 Linux (as measured) | 2.49 | 16.13 | 14252 |
| 8 Windows 11 | 2.51 | 16.28 | 16747 |

An earlier Windows variant that used no TCP timestamps at all sent about 9%
slower with TSO and LRO disabled. The same drop appears without the module when
timestamps are disabled in the stock kernel, so it comes from running without
timestamps, not from the module. Personality 8 does without timestamps only on
the connections the host opens.

## Limitations

- Only the first packets of a connection are shaped. Retransmission timing,
  congestion behaviour and everything above TCP remain FreeBSD's.
- Initial sequence numbers are not changed.
- IP IDs come from one counter; a real Linux host numbers each connection
  separately, which shows after the handshake.
- IPv4 only.
- The window scale can be lowered, not raised.
- The comparison with real hosts covers one Linux and one Windows machine. On
  Linux the window scale depends on the amount of memory.
- The personality is fixed until changed by hand.
- A tool that looks beyond the fields listed above can tell the difference.

## Caution

This module changes how a host answers on the network. It is meant for research
and for defensive use on machines you operate. Try it in a virtual machine
first.

## Papers

- 宮本大輔, 大江将史, 木村泰司, 門林雄基, "OS Fingerprint 対策手法の実装と評価",
  4th Workshop on Internet Technology (WIT2001), pp. 17–25, 2001 (in Japanese).
  [`legacy/miyamoto-wit2001.pdf`](legacy/miyamoto-wit2001.pdf)
- A report on the 2026 rewrite is in preparation.

## Related

[aoi](https://github.com/daisu-mi/aoi) (Anti OS Intrusion) is the companion of
this module: it records what an intruder does on the host.

## Contact

Daisuke Miyamoto — daisuke [ at ] iplove.net

## License

`freebsd/`, `linux/`, `common/` and `test/` are under the BSD 2-Clause license; see `LICENSE`.
`legacy/` contains files from the FreeBSD 4.3 source tree with modifications;
each file carries its original license notice.

---

## 日本語の説明

2001 年ごろに作った OS fingerprint 対策(FreeBSD 4.3 のカーネルパッチ)を、
FreeBSD 15.1 で読み込めるカーネルモジュールに作り直したものです。

- `freebsd/` が FreeBSD 15.1 用のモジュールです。カーネルのソースは書き換えません。
- `freebsd/jail/` は、jail ごとに別の OS に見せる手順です。
- `linux/` が Linux 用のモジュール、`linux/lxc/` がコンテナごとに使う手順です。Linux 版で確かめたのは 8 だけです。
- `legacy/` が 2001 年のパッチと、WIT2001 の論文、発表資料です。
- `sysctl net.inet.tcp.emu_kind=6` と `7` で Linux、`8` で Windows 11 に見せます。`0` で切ります。
- 6 は nmap のデータベースに合わせた Linux、7 は本物の Ubuntu 26.04.1 に合わせた Linux です。
- 8 は、本物の Windows 11 と nmap、p0f、JA4T で同じ結果になることを確かめています。
- 研究と防御のための道具です。まず仮想マシンで試してください。
