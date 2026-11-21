# aod — Anti OS Detection

A FreeBSD kernel module that makes a host answer OS fingerprinting tools as if
it ran a different operating system.

The first version was a patch to the FreeBSD 4.3 kernel, written in 2001. This
repository now holds a rewrite for FreeBSD 15.1 as a loadable module, next to
the original patch.

| Directory | Contents |
|---|---|
| `kld/` | The current module (FreeBSD 15.1, `pfil(9)` hooks, no change to the kernel source) |
| `test/` | Scripts used for the measurements, and the raw Nmap output |
| `legacy/` | The 2001 patch for FreeBSD 4.3, its source tree, and the WIT2001 paper and slides |

## What it does

With the module loaded and a personality selected, Nmap 7.98 reports:

| `net.inet.tcp.emu_kind` | Personality | Nmap `-O` result |
|---|---|---|
| 0 | off | no exact match (guesses FreeBSD 12–13) |
| 6 | Linux | exact: Linux 4.15 – 5.19 |
| 7 | Windows 11 | exact: Microsoft Windows 10 1703 or Windows 11 21H2 |
| 8 | Windows 11, no TCP timestamps | exact: Microsoft Windows 10 1709 – 21H2 |

Values 1 to 5 are the personalities of the 2001 version (FreeBSD, NetBSD,
Windows, Windows 2000, Cisco). They are kept for reference and do not match
anything in a current Nmap database.

p0f 3.09b reports the outbound SYN of personality 6 as Linux and of
personality 8 as Windows NT kernel. Personality 7 is not recognized by p0f,
because Windows does not use TCP timestamps by default; use 8 if passive tools
matter.

With the Windows personalities, FIN, NULL and Xmas scans show every port as
closed, as they do against Windows. SYN and connect scans show the true state
with every personality.

## Build and use

On FreeBSD 15.1 with the kernel sources in `/usr/src`:

```
cd kld
make
kldload ./aod.ko
sysctl net.inet.tcp.emu_kind=6
```

To stop: `sysctl net.inet.tcp.emu_kind=0`, then `kldunload aod`.

While a personality is active the module turns off per-connection TCP timestamp
offsets (`net.inet.tcp.ts_offset_per_conn`). The previous value is restored
when the personality is switched off or the module is unloaded.

## How it works

Two hooks are registered on the IPv4 `pfil` head. The module keeps no
per-connection state.

- Outbound: TTL, DF, IP ID, the window of SYN and SYN/ACK, the order of TCP
  options, the window scale value, the acknowledgment field of a bare RST, the
  code of an ICMP echo reply.
- Inbound: clears the ECN bits of a SYN, blanks a timestamp option, and answers
  by itself the segments that the imitated system treats differently (no flags,
  SYN+FIN, FIN without ACK).

## Cost

Measured in a QEMU/KVM guest (8 vCPU) against the host over a virtual link;
medians of five rounds. Differences below about ten percent are not resolved by
this setup.

| Condition | receive Gbit/s | send Gbit/s | connections/s |
|---|---|---|---|
| no module | 2.46 | 17.43 | 13212 |
| loaded, off | 2.38 | 16.50 | 16264 |
| Linux | 2.41 | 17.54 | 14429 |
| Windows 11 | 2.51 | 17.84 | 15872 |
| Windows 11, no timestamps | 2.46 | 16.95 | 15295 |

With TSO and LRO disabled, personality 8 sends about 9% slower. The same drop
appears without the module when timestamps are disabled in the stock kernel, so
it comes from running without timestamps, not from the module.

## Limitations

- Only the first packets of a connection are shaped. Retransmission timing,
  congestion behaviour and everything above TCP remain FreeBSD's.
- Initial sequence numbers are not changed.
- IPv4 only. Only the default vnet.
- The window scale can be lowered, not raised.
- The Windows values come from the Nmap database and documentation. They were
  not compared with packets from a Windows host.
- The personality is fixed until changed by hand.
- A tool that looks beyond the fields listed above can tell the difference.

## Caution

This module changes how a host answers on the network. It is meant for research
and for defensive use on machines you operate. Try it in a virtual machine
first; `test/vm/` has the scripts used for that.

## Papers

- 宮本大輔, 大江将史, 木村泰司, 門林雄基, "OS Fingerprint 対策手法の実装と評価",
  4th Workshop on Internet Technology (WIT2001), pp. 17–25, 2001 (in Japanese).
  [`legacy/miyamoto-wit2001.pdf`](legacy/miyamoto-wit2001.pdf)
- A report on the 2026 rewrite is in preparation.

## License

`kld/` and `test/` are under the BSD 2-Clause license; see `LICENSE`.
`legacy/` contains files from the FreeBSD 4.3 source tree with modifications;
each file carries its original license notice.

---

## 日本語の説明

2001 年ごろに作った OS fingerprint 対策(FreeBSD 4.3 のカーネルパッチ)を、
FreeBSD 15.1 で読み込めるカーネルモジュールに作り直したものです。

- `kld/` が今のモジュールです。カーネルのソースは書き換えません。
- `legacy/` が 2001 年のパッチと、WIT2001 の論文、発表資料です。
- `sysctl net.inet.tcp.emu_kind=6` で Linux、`7` と `8` で Windows 11 に見せます。`0` で切ります。
- nmap 7.98 の OS 判定で、3 つとも完全一致になることを確かめています。
- 研究と防御のための道具です。まず仮想マシンで試してください。
