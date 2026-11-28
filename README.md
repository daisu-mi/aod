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
| 0 | off | no exact match (first guess Android 4.0, 93%; then FreeBSD 12–13, 92%) | FreeBSD |
| 6 | Linux, as in the Nmap database | exact: Linux 4.15 – 5.19, usually with other Linux-based entries (see below) | Linux 2.2.x-3.x |
| 7 | Linux, as measured on Ubuntu 26.04.1 | no exact match; best guess Linux 4.15 – 5.19 (97%) | Linux 2.2.x-3.x |
| 8 | Windows 11 | exact: Microsoft Windows 10 1703 or Windows 11 21H2 | Windows NT kernel |

Each personality was compared with a real host on the same test network:

- **Windows 11** (build 22621). Nmap, p0f and JA4T give personality 8 and the
  real host the same result. In the Nmap fingerprints every test line from OPS
  to IE is identical; the SEQ line differs only in two measured values that
  also vary between runs of the same host.
- **Ubuntu 26.04.1** (Linux 7.0). Nmap reports no exact match for the real
  host. No entry of its database names Linux 7; the newest kernel that an
  entry name gives is 6.2 ("Linux 5.0 - 6.2"). Personality 7 gets the same
  non-match, with the same list of guesses. Personality 6 follows the database
  entry "Linux 6.0" instead and is an exact match. Pick 6 to satisfy the
  tool, 7 to look like a current machine.
  With 6, Nmap can list several database entries for one exact match. Linux
  4.15 – 5.19 is always first. Of the 13 scans of the host with personality 6
  under `test/results/`, ten also list OpenWrt 21.02 (Linux 5.4) and MikroTik
  RouterOS 7.2 – 7.5 (Linux 5.6.3), two only OpenWrt, and one neither; both
  are Linux-based. `test/results/kind6-rerun/` holds six of these scans.

With personality 8, FIN, NULL and Xmas scans show every port as closed, as they
do against Windows. SYN and connect scans show the true state with every
personality.

### IPv6

Both modules also work on IPv6. Nmap identifies IPv6 hosts with a separate
classifier, and its labels differ from those of the table above; the Windows
label names older systems. Each row is five scans with
`nmap -6 -O`; all five gave the same verdict.

| Target | Personality | Nmap 7.98 `-6 -O` |
|---|---|---|
| FreeBSD 15.1 with the module | 0, off | no match (guess: FreeBSD 12, 91%) |
| | 6, Linux (database) | exact: Linux 4.19 |
| | 7, Linux (as measured) | exact: Linux 4.19 |
| | 8, Windows 11 | exact: Microsoft Windows Vista, Windows 7 SP1, Windows Server 2008 R2 or Windows 8.1 |
| Ubuntu 26.04.1 with the module | 0, off | exact: Linux 4.19 |
| | 8, Windows 11 | exact: Microsoft Windows Vista, Windows 7 SP1, Windows Server 2008 R2 or Windows 8.1 |
| a real Windows 11 (build 22621) | | exact: Microsoft Windows Vista, Windows 7 SP1, Windows Server 2008 R2 or Windows 8.1 |

Personality 8 gets the label that the real Windows 11 gets, and personalities
6 and 7 on FreeBSD get the label of the real Linux host. "Exact" means that
Nmap printed the label without marking it as a guess; it does not mean that
the replies are identical. The replies of 6 and 7 still differ from those of
the Ubuntu host in fields that Nmap records (SYN/ACK window, the reply to an
echo request with a nonzero code, flow label). Before the IPv6 hooks
were added, a FreeBSD host set to 8 was, in one scan, still guessed to be
FreeBSD over IPv6 (FreeBSD 12.X, 91%) while it was reported as Windows over
IPv4.

A jail with its own network stack (FreeBSD) and a network namespace (Linux)
keep their own personality over IPv6 as well. The IPv4 verdicts did not
change. The raw output is in `test/results/ipv6/`. Two jails and a Linux network
namespace were scanned again on 28 November 2026 with the modules built from
this source, before and after their setting, over IPv4 and IPv6
(`test/results/rescan-2026-11-28/`).

Values 1 to 5 are the personalities of the 2001 version (FreeBSD, NetBSD,
Windows, Windows 2000, Cisco). They are kept for reference, and only in part:
1 passes packets unchanged; for 2 to 5 the module sets the TTL, the DF bit,
the IP ID step, fixed SYN and SYN/ACK windows, the reply to a segment without
flags and, where the 2001 source has them, the SYN+FIN drop and echo reply
code 0. It leaves out the sequence number generators, the TCP option changes,
the further window rules, the replies to FIN, PSH and URG segments and the
other UDP and ICMP changes of the 2001 source. In five IPv4 scans of each,
Nmap 7.98 reported no exact match (`test/results/personalities-2001/`);
which of these omissions, if any, is the reason was not tested.

## Build and use

On FreeBSD 15.1 with the kernel sources in `/usr/src`:

```
cd freebsd
make
kldload ./aod.ko
sysctl net.inet.tcp.emu_kind=8
```

To stop: `sysctl net.inet.tcp.emu_kind=0`, then `kldunload aod`.

While personality 6 or 8 is active the module turns off per-connection TCP
timestamp offsets (`net.inet.tcp.ts_offset_per_conn`). The previous value is restored
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
Microsoft Windows 10 1703 or Windows 11 21H2. The IPv6 result is in the table
above. The other numbers in "What it does" and "Cost" were not measured with
it.

## How it works

Two hooks are registered on the IPv4 `pfil` head of each network stack and
two on the IPv6 head (on Linux, netfilter hooks in each network namespace).
The module keeps no per-connection state.

- Outbound: TTL, DF, IP ID, the window of SYN and SYN/ACK, the order of TCP
  options, the timestamp option of the host's own SYN, the window scale value,
  the acknowledgment field of a bare RST, the code of an ICMP echo reply.
- Inbound: clears the ECN bits of a SYN, and answers or drops by itself some segments
  that the imitated system treats differently (for example no flags, or FIN,
  PSH or URG without ACK).
- IPv6: the hop limit takes the place of the TTL, and the TCP handling is the
  same code. Four things were added for personality 8 after comparing with
  the real Windows 11: the window of a SYN/ACK is rounded to the IPv6 minimum
  segment size, an echo request with a nonzero code is answered with code 0,
  a solicited neighbor advertisement carries the override flag and the
  link-layer address, and the acknowledgment field of a bare RST repeats its
  sequence field. The flow label and other ICMPv6 messages are left as the
  kernel sends them.

## Cost

Measured in a QEMU/KVM guest (8 vCPU) against the host over a virtual link;
medians of five rounds, over IPv4, on the build of 21 November 2026, before
the IPv6 hooks were added. In the sending direction the five rounds of one
condition span about 10 to 18 percent of their median, so smaller differences are
not resolved by this setup.

| Condition | receive Gbit/s | send Gbit/s | connections/s |
|---|---|---|---|
| no module | 2.50 | 16.64 | 14828 |
| loaded, off | 2.53 | 16.01 | 14483 |
| 6 Linux (database) | 2.49 | 16.03 | 16537 |
| 7 Linux (as measured) | 2.49 | 16.13 | 14252 |
| 8 Windows 11 | 2.51 | 16.28 | 16747 |

An earlier Windows variant that used no TCP timestamps at all sent about 9%
slower with TSO and LRO disabled. Without the module, with timestamps
disabled in the stock kernel, sending was slower as well, which points to the
missing timestamps and not only to the module's work; the two contributions
were not separated. Personality 8 does without timestamps only on
the connections the host opens, and their cost was not measured.

## Limitations

- Windows and options are shaped only on SYN and SYN/ACK segments. The TTL
  (or hop limit) and the IP ID are also set on later packets, but IPv4
  fragments and TSO bursts pass unchanged. Retransmission timing,
  congestion behaviour and everything above TCP remain FreeBSD's.
- Initial sequence numbers are not changed.
- IP IDs come from one counter per network stack. Across three connections
  the IDs of the Linux personalities ran on from one connection to the next,
  and those of the Ubuntu host did not; how Linux assigns them was not
  examined.
- Over IPv6, TCP is shaped only when its header follows the IPv6 header
  directly. The 2001 personalities were not scanned over IPv6, and Nmap was
  the only tool run there; no passive tool was tried and the cost was not
  measured again.
- The window scale can be lowered, not raised.
- The comparison with real hosts covers one Windows 11 guest and two Ubuntu
  26.04.1 guests with the same kernel version. The window scale of a Linux
  host is not fixed: the 2 GB guests advertised 8 and the scanning host 10.
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
- D. Miyamoto, "Anti OS Fingerprinting, Revisited: A Loadable Kernel Module
  for FreeBSD and What Twenty-Five Years Changed", arXiv:2611.28651, 2026.
  <https://arxiv.org/abs/2611.28651> (covers the FreeBSD module on one
  network stack)

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
- IPv6 にも対応しています。nmap の IPv6 の判定で、8 は本物の Windows 11 と同じ判定、FreeBSD 上の 6 と 7 は本物の Linux と同じ判定になります。判定が同じというだけで、返事の中身がすべて同じではありません。
- 研究と防御のための道具です。まず仮想マシンで試してください。
