# One personality per container

The module in `linux/` keeps its setting and its hooks per network namespace.
A container with its own network namespace gets its own
`net.ipv4.tcp_emu_kind`. The host and each container can then answer a
scanner as different systems, on one kernel.

## Example

This is the arrangement used for the measurement: an unprivileged LXC
container named `hp`, with a second interface on a bridge that faces the
scanner. Added to the container's `config`:

```
lxc.net.1.type = veth
lxc.net.1.link = brtest
lxc.net.1.flags = up
lxc.net.1.ipv4.address = 10.99.0.14/30
```

On the host:

```
insmod ./aod_linux.ko
lxc-start -n hp
pid=$(lxc-info -n hp -p | awk '{print $2}')
nsenter -t "$pid" -n sysctl -w net.ipv4.tcp_emu_kind=8
```

## Who can change it

Only root of the host can write the setting. Root inside the container is
refused, so no separate lock is needed. The value of a container is set from
the host with `nsenter`, as above.

Root inside the container can still change other settings of its own network
namespace, such as `tcp_timestamps` and `tcp_ecn`, which the module relies on.

## Measurement

Ubuntu 26.04.1, Linux 7.0.0-43, LXC 6.0.6. Nmap 7.98, `-O`, from a prober on
the same closed link.

| Target | `tcp_emu_kind` | Nmap verdict |
|---|---|---|
| host, 10.99.0.6 | 0 | no exact match (best guess Linux 4.15 – 5.19, 97%) |
| container, 10.99.0.14 | 0 | no exact match (same guesses) |
| container, 10.99.0.14 | 8 | exact: Microsoft Windows 10 1703 or Windows 11 21H2 |

- Under scanning, 30 rounds of unload and load all succeeded.
- A 50 MB transfer in each direction arrived with the same hash, and no packet
  was dropped for a bad checksum.

Only personality 8 was tested on Linux.

`results/` holds the raw Nmap output.
