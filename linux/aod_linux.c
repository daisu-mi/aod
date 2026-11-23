// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Daisuke Miyamoto
 *
 * aod for Linux: Anti OS Detection as a netfilter module.
 * Lineage: daisu-mi/aod (2001, FreeBSD 4.3 kernel patch) and its pfil KLD
 * port for FreeBSD 15.1 (../freebsd/aod.c).  The profile table and the option
 * handling are the same code.  Research/defensive use.  Run in an isolated VM.
 *
 * Written against Linux 7.0 (Ubuntu 26.04.1).
 *
 * Two netfilter hooks per network namespace, so a container with its own
 * network namespace can look like one system while the host and the other
 * containers look like others:
 *
 *   LOCAL_OUT: TTL, IP id, window and option order on SYN|ACK and SYN,
 *              ack field of bare RST, ICMP echo reply code
 *   LOCAL_IN:  replies to odd-flag probes
 *
 * The timestamp clock and ECN are switched with the namespace's own
 * tcp_timestamps and tcp_ecn settings, and put back afterwards.
 *
 * net.ipv4.tcp_emu_kind selects the personality of the namespace the
 * caller is in.  Only root of the host may write it; set a container's
 * value with: nsenter -t <pid of the container> -n sysctl -w ...
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/random.h>
#include <linux/sysctl.h>
#include <linux/capability.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/checksum.h>

#include "aod.h"

#define	AOD_WIN4(w)	{ { (w), (w) }, { (w), (w) } }

/*
 * 1 to 5: values from the last 2001 version (legacy/src/netinet).
 *         FreeBSD (1) is left as the kernel sends it, as in the original.
 * 6, 7:   values from nmap-os-db of nmap 7.98.
 */
static const struct aod_profile aod_profiles[AOD_EMU_MAX + 1] = {
	[AOD_EMU_OFF] = { .kind = AOD_EMU_OFF },
	[AOD_EMU_FREEBSD] = { .kind = AOD_EMU_FREEBSD },
	[AOD_EMU_NETBSD] = {
		.kind = AOD_EMU_NETBSD,
		.synack_win = AOD_WIN4(0x4000), .syn_win = 0x4000,
		.ttl = 64, .icmp_ttl = 255,
		.set_df = AOD_DF_OFF, .ipid_stride = 1,
		.null_reply = AOD_NULL_RSTACK,
	},
	[AOD_EMU_WINDOWS] = {
		.kind = AOD_EMU_WINDOWS,
		.synack_win = AOD_WIN4(0x2017), .syn_win = 0x2000,
		.ttl = 128, .icmp_ttl = 128,
		.set_df = AOD_DF_ON, .ipid_stride = 256,
		.null_reply = AOD_NULL_RSTACK_SEQ, .echo_code0 = 1,
	},
	[AOD_EMU_WIN2K] = {
		.kind = AOD_EMU_WIN2K,
		.synack_win = AOD_WIN4(0x402e), .syn_win = 0x4000,
		.ttl = 128, .icmp_ttl = 128,
		.set_df = AOD_DF_ON, .ipid_stride = 1,
		.null_reply = AOD_NULL_RSTACK_SEQ,
		.synfin_reply = AOD_SYNFIN_DROP, .echo_code0 = 1,
	},
	[AOD_EMU_CISCO] = {
		.kind = AOD_EMU_CISCO,
		.synack_win = AOD_WIN4(0x1020), .syn_win = 0x1020,
		.ttl = 255, .icmp_ttl = 255,
		.set_df = AOD_DF_OFF, .ipid_stride = 1,
		.ipid_zero_on_syn = 1,
		.null_reply = AOD_NULL_RSTACK,
	},
	[AOD_EMU_LINUX] = {
		.kind = AOD_EMU_LINUX,
		/* 44 * 1460 without timestamps, 45 * 1448 with */
		.synack_win = { { 0xfaf0, 0xfaf0 }, { 0xfe88, 0xfe88 } },
		.syn_win = 0xfaf0,
		.ttl = 64, .icmp_ttl = 64,
		.opt_order = AOD_OPT_LINUX, .wscale = 7,
		.ts_per_host = 1,
		/* id 0 on SYN|ACK and RST, counting on everything else */
		.ipid_stride = 1, .ipid_tcp_only = 1,
		.synfin_reply = AOD_SYNFIN_DROP,
	},
	[AOD_EMU_WIN11] = {
		.kind = AOD_EMU_WIN11,
		.synack_win = { { 0xff70, 0xffff }, { 0xffdc, 0xffff } },
		.syn_win = 0xfaf0,
		.ttl = 128, .icmp_ttl = 128,
		.ipid_stride = 1,
		.opt_order = AOD_OPT_WINDOWS, .wscale = 8,
		.no_ecn = 1, .ts_per_host = 1,
		/* accepts timestamps when asked, never asks for them */
		.strip_ts = 1,
		.null_reply = AOD_NULL_RSTACK,
		.synfin_reply = AOD_SYNFIN_RSTACK, .rst_noack = 1,
		.rst_ack_other = 1, .echo_code0 = 1,
	},
	/*
	 * A 2 GB Ubuntu 26.04.1 guest as we measured it: window scale 8
	 * (FreeBSD's own value) and a timestamp clock that differs per
	 * connection (also FreeBSD's default), otherwise as AOD_EMU_LINUX.
	 */
	[AOD_EMU_LINUX7] = {
		.kind = AOD_EMU_LINUX7,
		.synack_win = { { 0xfaf0, 0xfaf0 }, { 0xfe88, 0xfe88 } },
		.syn_win = 0xfaf0,
		.ttl = 64, .icmp_ttl = 64,
		.opt_order = AOD_OPT_LINUX,
		.ipid_stride = 1, .ipid_tcp_only = 1,
		.synfin_reply = AOD_SYNFIN_DROP,
	},
};

/* One set per network namespace. */
struct aod_net {
	int		kind;
	atomic_t	ipid;		/* next IP id, host byte order */
	int		saved_ts;	/* tcp_timestamps before we changed it, -1: untouched */
	int		saved_ecn;	/* tcp_ecn, same */
	struct ctl_table_header *sysctl;
	struct ctl_table *table;
};

static unsigned int aod_net_id __read_mostly;

static struct aod_net *
aod_pernet(const struct net *net)
{
	return (net_generic(net, aod_net_id));
}

/*
 * Linux gives every connection its own timestamp offset unless
 * tcp_timestamps is 2.  Windows keeps one clock, and nmap measures that.
 */
static void
aod_apply(struct net *net, struct aod_net *an, int kind)
{
	const struct aod_profile *p = &aod_profiles[kind];

	if (p->ts_per_host) {
		if (an->saved_ts < 0)
			an->saved_ts = READ_ONCE(net->ipv4.sysctl_tcp_timestamps);
		WRITE_ONCE(net->ipv4.sysctl_tcp_timestamps, 2);
	} else if (an->saved_ts >= 0) {
		WRITE_ONCE(net->ipv4.sysctl_tcp_timestamps, an->saved_ts);
		an->saved_ts = -1;
	}
	if (p->no_ecn) {
		if (an->saved_ecn < 0)
			an->saved_ecn = READ_ONCE(net->ipv4.sysctl_tcp_ecn);
		WRITE_ONCE(net->ipv4.sysctl_tcp_ecn, 0);
	} else if (an->saved_ecn >= 0) {
		WRITE_ONCE(net->ipv4.sysctl_tcp_ecn, an->saved_ecn);
		an->saved_ecn = -1;
	}
	WRITE_ONCE(an->kind, kind);
}

static int
aod_sysctl_kind(const struct ctl_table *ctl, int write, void *buffer,
    size_t *lenp, loff_t *ppos)
{
	struct aod_net *an = ctl->extra1;
	struct net *net = ctl->extra2;
	int val = an->kind, ret;
	struct ctl_table tmp = {
		.data = &val, .maxlen = sizeof(int), .mode = ctl->mode,
	};

	/* root of the host only: root inside a container must not switch it off */
	if (write && !capable(CAP_NET_ADMIN))
		return (-EPERM);
	ret = proc_dointvec(&tmp, write, buffer, lenp, ppos);
	if (ret != 0 || !write)
		return (ret);
	if (val < AOD_EMU_OFF || val > AOD_EMU_MAX)
		return (-EINVAL);
	aod_apply(net, an, val);
	return (0);
}

static uint16_t
aod_next_ipid(struct aod_net *an, const struct aod_profile *p, bool syn)
{
	unsigned int stride, id;

	stride = p->ipid_stride;
	if (syn && p->ipid_zero_on_syn) {
		atomic_set(&an->ipid, stride);
		return (0);
	}
	do {
		id = atomic_fetch_add(stride, &an->ipid);
		if (stride > 1)
			id -= id % stride;
	} while (stride == 1 && (uint16_t)id == 0);	/* 0 means "not set" */
	return ((uint16_t)id);
}

/*
 * Replace len bytes (even, 16 bit aligned in the packet).  The helper
 * leaves the checksum alone when it is still pending (CHECKSUM_PARTIAL:
 * only the pseudo header is summed so far) and fixes it up otherwise.
 */
static void
aod_replace(struct sk_buff *skb, struct tcphdr *th, uint8_t *dst,
    const uint8_t *src, int len)
{
	__be16 o, n;
	int i;

	for (i = 0; i + 1 < len; i += 2) {
		memcpy(&o, dst + i, 2);
		memcpy(&n, src + i, 2);
		if (o == n)
			continue;
		memcpy(dst + i, &n, 2);
		inet_proto_csum_replace2(&th->check, skb, o, n, false);
	}
}

/*
 * TCP options of a SYN or SYN|ACK.
 */
struct aod_opts {
	bool		mss, ws, sack, ts, other;
	uint8_t		mssval[2], wsval, tsval[8];
};

static void
aod_opts_parse(const uint8_t *cp, int len, struct aod_opts *o)
{
	int opt, optlen;

	memset(o, 0, sizeof(*o));
	for (; len > 0; cp += optlen, len -= optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP) {
			optlen = 1;
			continue;
		}
		if (len < 2 || (optlen = cp[1]) < 2 || optlen > len) {
			o->other = true;
			break;
		}
		if (opt == TCPOPT_MSS && optlen == TCPOLEN_MSS) {
			o->mss = true;
			memcpy(o->mssval, cp + 2, 2);
		} else if (opt == TCPOPT_WINDOW && optlen == TCPOLEN_WINDOW) {
			o->ws = true;
			o->wsval = cp[2];
		} else if (opt == TCPOPT_SACK_PERM &&
		    optlen == TCPOLEN_SACK_PERM) {
			o->sack = true;
		} else if (opt == TCPOPT_TIMESTAMP &&
		    optlen == TCPOLEN_TIMESTAMP) {
			o->ts = true;
			memcpy(o->tsval, cp + 2, 8);
		} else
			o->other = true;
	}
}

/* Returns the length written.  buf holds TCP_MAXOLEN bytes. */
static int
aod_opts_emit(int order, const struct aod_opts *o, uint8_t *buf)
{
	uint8_t *cp = buf;
	int pass;

	*cp++ = TCPOPT_MSS;
	*cp++ = TCPOLEN_MSS;
	memcpy(cp, o->mssval, 2);
	cp += 2;
	/* Windows puts the window scale first, Linux puts it last */
	for (pass = 0; pass < 2; pass++) {
		if ((pass == 0) == (order == AOD_OPT_WINDOWS)) {
			if (o->ws) {
				*cp++ = TCPOPT_NOP;
				*cp++ = TCPOPT_WINDOW;
				*cp++ = TCPOLEN_WINDOW;
				*cp++ = o->wsval;
			}
			continue;
		}
		if (o->sack && o->ts) {
			*cp++ = TCPOPT_SACK_PERM;
			*cp++ = TCPOLEN_SACK_PERM;
		} else if (o->sack || o->ts) {
			*cp++ = TCPOPT_NOP;
			*cp++ = TCPOPT_NOP;
		}
		if (o->ts) {
			*cp++ = TCPOPT_TIMESTAMP;
			*cp++ = TCPOLEN_TIMESTAMP;
			memcpy(cp, o->tsval, 8);
			cp += 8;
		} else if (o->sack) {
			*cp++ = TCPOPT_SACK_PERM;
			*cp++ = TCPOLEN_SACK_PERM;
		}
	}
	return (cp - buf);
}

/* Outbound TCP. */
static void
aod_out_tcp(const struct aod_profile *p, struct sk_buff *skb,
    struct iphdr *iph, struct tcphdr *th)
{
	struct aod_opts o;
	uint8_t buf[MAX_TCP_OPTION_SPACE], *optp;
	__be32 ack;
	__be16 new16;
	uint16_t win;
	int optlen, newlen;

	if (p->set_df == AOD_DF_ON)
		iph->frag_off |= htons(IP_DF);
	else if (p->set_df == AOD_DF_OFF)
		iph->frag_off &= ~htons(IP_DF);

	/* T4 and T6 of nmap: Windows leaves something in the ack field */
	if (p->rst_ack_other && th->rst && !th->ack && !th->syn && !th->fin &&
	    th->ack_seq == 0) {
		ack = (__force __be32)get_random_u32() | htonl(0x00010000);
		aod_replace(skb, th, (uint8_t *)&th->ack_seq, (uint8_t *)&ack, 4);
	}

	if (!th->syn || th->fin || th->rst)
		return;

	memset(&o, 0, sizeof(o));
	optlen = (th->doff << 2) - (int)sizeof(struct tcphdr);
	optp = (uint8_t *)(th + 1);
	if (optlen > 0 && optlen <= MAX_TCP_OPTION_SPACE) {
		aod_opts_parse(optp, optlen, &o);
		if (p->opt_order != AOD_OPT_LEAVE && o.mss && !o.other) {
			/* a smaller shift only makes the peer see less room */
			if (o.ws && p->wscale != 0 && p->wscale < o.wsval)
				o.wsval = p->wscale;
			memset(buf, 0, sizeof(buf));
			newlen = aod_opts_emit(p->opt_order, &o, buf);
			/* same length only; Linux pads the same way */
			if (newlen == optlen)
				aod_replace(skb, th, optp, buf, optlen);
		}
	}

	win = th->ack ? p->synack_win[o.ts][o.ws] : p->syn_win;
	if (win != 0) {
		new16 = htons(win);
		aod_replace(skb, th, (uint8_t *)&th->window, (uint8_t *)&new16, 2);
	}
}

/*
 * Outbound hook.  The IP header checksum is already there at this point,
 * so it is computed again at the end.
 */
static unsigned int
aod_hook_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct aod_net *an = aod_pernet(state->net);
	const struct aod_profile *p;
	struct iphdr *iph;
	struct tcphdr *th = NULL;
	struct icmphdr *icmph;
	bool syn = false, setid;
	uint8_t ttl;
	int kind, hlen, need;

	kind = READ_ONCE(an->kind);
	if (kind <= AOD_EMU_FREEBSD || kind > AOD_EMU_MAX)
		return (NF_ACCEPT);
	p = &aod_profiles[kind];

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return (NF_ACCEPT);
	iph = ip_hdr(skb);
	hlen = iph->ihl << 2;
	/* leave fragments and segmentation offload bursts alone */
	if (iph->version != 4 || hlen < (int)sizeof(struct iphdr) ||
	    ip_is_fragment(iph) || skb_is_gso(skb))
		return (NF_ACCEPT);
	need = hlen;
	if (iph->protocol == IPPROTO_TCP)
		need += sizeof(struct tcphdr);
	else if (iph->protocol == IPPROTO_ICMP)
		need += sizeof(struct icmphdr);
	if (skb->len < need)
		return (NF_ACCEPT);
	if (iph->protocol == IPPROTO_TCP) {
		if (!pskb_may_pull(skb, need))
			return (NF_ACCEPT);
		th = (struct tcphdr *)(skb_network_header(skb) + hlen);
		need = hlen + (th->doff << 2);
		if (th->doff < 5 || skb->len < need)
			return (NF_ACCEPT);
	}
	if (skb_ensure_writable(skb, need) != 0)
		return (NF_ACCEPT);
	iph = ip_hdr(skb);

	/* TTL: only when the sender left the system default */
	ttl = iph->protocol == IPPROTO_ICMP ? p->icmp_ttl : p->ttl;
	if (ttl != 0 && iph->ttl == READ_ONCE(state->net->ipv4.sysctl_ip_default_ttl))
		iph->ttl = ttl;

	setid = p->ipid_stride != 0 && !p->ipid_tcp_only;
	if (iph->protocol == IPPROTO_TCP) {
		th = (struct tcphdr *)((uint8_t *)iph + hlen);
		aod_out_tcp(p, skb, iph, th);
		syn = th->syn;
		if (p->ipid_tcp_only)
			setid = !th->rst && !(th->syn && th->ack);
	} else if (iph->protocol == IPPROTO_ICMP) {
		icmph = (struct icmphdr *)((uint8_t *)iph + hlen);
		if (p->echo_code0 && icmph->type == ICMP_ECHOREPLY &&
		    icmph->code != 0) {
			__be16 o, n;

			memcpy(&o, icmph, 2);
			icmph->code = 0;
			memcpy(&n, icmph, 2);
			csum_replace2(&icmph->checksum, o, n);
		}
	}

	if (setid)
		iph->id = htons(aod_next_ipid(an, p, syn));
	ip_send_check(iph);
	return (NF_ACCEPT);
}

/*
 * Send a bare TCP segment back to the sender of (oiph, oth).
 * seq and ack are in network byte order.
 */
static void
aod_tcp_reply(struct net *net, const struct iphdr *oiph,
    const struct tcphdr *oth, __be32 seq, __be32 ack)
{
	struct flowi4 fl4 = {
		.daddr = oiph->saddr, .saddr = oiph->daddr,
		.flowi4_proto = IPPROTO_TCP,
	};
	struct sk_buff *nskb;
	struct rtable *rt;
	struct iphdr *iph;
	struct tcphdr *th;

	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return;
	nskb = alloc_skb(sizeof(*iph) + sizeof(*th) + LL_MAX_HEADER, GFP_ATOMIC);
	if (nskb == NULL) {
		ip_rt_put(rt);
		return;
	}
	skb_reserve(nskb, LL_MAX_HEADER);
	skb_dst_set(nskb, &rt->dst);
	nskb->protocol = htons(ETH_P_IP);

	skb_reset_network_header(nskb);
	iph = skb_put_zero(nskb, sizeof(*iph));
	iph->version = 4;
	iph->ihl = sizeof(*iph) >> 2;
	iph->frag_off = htons(IP_DF);
	iph->ttl = ip4_dst_hoplimit(&rt->dst);
	iph->protocol = IPPROTO_TCP;
	iph->saddr = oiph->daddr;
	iph->daddr = oiph->saddr;

	skb_reset_transport_header(nskb);
	th = skb_put_zero(nskb, sizeof(*th));
	th->source = oth->dest;
	th->dest = oth->source;
	th->seq = seq;
	th->ack_seq = ack;
	th->doff = sizeof(*th) >> 2;
	th->rst = 1;
	th->ack = 1;
	th->check = ~tcp_v4_check(sizeof(*th), iph->saddr, iph->daddr, 0);
	nskb->ip_summed = CHECKSUM_PARTIAL;
	nskb->csum_start = (unsigned char *)th - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);

	ip_local_out(net, NULL, nskb);	/* passes aod_hook_out like any other */
}

/* Inbound hook: only what is addressed to this namespace gets here. */
static unsigned int
aod_hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct aod_net *an = aod_pernet(state->net);
	const struct aod_profile *p;
	struct iphdr *iph;
	struct tcphdr *th;
	int kind, hlen, tlen;

	kind = READ_ONCE(an->kind);
	if (kind <= AOD_EMU_FREEBSD || kind > AOD_EMU_MAX)
		return (NF_ACCEPT);
	p = &aod_profiles[kind];

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return (NF_ACCEPT);
	iph = ip_hdr(skb);
	hlen = iph->ihl << 2;
	if (iph->version != 4 || iph->protocol != IPPROTO_TCP ||
	    hlen < (int)sizeof(struct iphdr) || ip_is_fragment(iph) ||
	    skb->pkt_type != PACKET_HOST ||
	    !pskb_may_pull(skb, hlen + sizeof(struct tcphdr)))
		return (NF_ACCEPT);
	iph = ip_hdr(skb);
	th = (struct tcphdr *)((uint8_t *)iph + hlen);

	if (!th->syn && !th->fin && !th->rst && !th->ack && !th->psh &&
	    !th->urg && p->null_reply != AOD_NULL_LEAVE) {
		aod_tcp_reply(state->net, iph, th,
		    p->null_reply == AOD_NULL_RSTACK_SEQ ? th->ack_seq : 0,
		    th->seq);
		return (NF_DROP);
	}

	/*
	 * FIN, PSH or URG with none of SYN, RST and ACK: some stacks reset
	 * these even on a listening port, which makes FIN and Xmas scans
	 * report every port as closed.
	 */
	if (p->rst_noack && !th->syn && !th->rst && !th->ack) {
		tlen = (int)ntohs(iph->tot_len) - hlen - (th->doff << 2);
		if (tlen < 0)
			tlen = 0;
		if (th->fin)
			tlen++;
		aod_tcp_reply(state->net, iph, th, 0,
		    htonl(ntohl(th->seq) + tlen));
		return (NF_DROP);
	}

	if (th->syn && th->fin && !th->rst && !th->ack) {
		if (p->synfin_reply == AOD_SYNFIN_RSTACK)
			aod_tcp_reply(state->net, iph, th, 0,
			    htonl(ntohl(th->seq) + 2));
		if (p->synfin_reply != AOD_SYNFIN_LEAVE)
			return (NF_DROP);
	}
	return (NF_ACCEPT);
}

static const struct nf_hook_ops aod_hooks[] = {
	{
		.hook = aod_hook_out, .pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT, .priority = NF_IP_PRI_LAST,
	},
	{
		.hook = aod_hook_in, .pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN, .priority = NF_IP_PRI_FIRST,
	},
};

/* Runs for every namespace: at load for those that exist, later for new ones. */
static int __net_init
aod_net_init(struct net *net)
{
	struct aod_net *an = aod_pernet(net);
	int error;

	an->kind = AOD_EMU_OFF;
	an->saved_ts = an->saved_ecn = -1;
	atomic_set(&an->ipid, get_random_u32());

	/* Same name as the 2001 version (net.inet.tcp.emu_kind there). */
	an->table = kzalloc(sizeof(*an->table), GFP_KERNEL);
	if (an->table == NULL)
		return (-ENOMEM);
	an->table->procname = "tcp_emu_kind";
	an->table->mode = 0644;
	an->table->proc_handler = aod_sysctl_kind;
	an->table->extra1 = an;
	an->table->extra2 = net;
	an->sysctl = register_net_sysctl_sz(net, "net/ipv4", an->table, 1);
	if (an->sysctl == NULL) {
		kfree(an->table);
		return (-ENOMEM);
	}
	error = nf_register_net_hooks(net, aod_hooks, ARRAY_SIZE(aod_hooks));
	if (error != 0) {
		unregister_net_sysctl_table(an->sysctl);
		kfree(an->table);
	}
	return (error);
}

/* Runs for every namespace: when it goes away, and for all of them at unload. */
static void __net_exit
aod_net_exit(struct net *net)
{
	struct aod_net *an = aod_pernet(net);

	nf_unregister_net_hooks(net, aod_hooks, ARRAY_SIZE(aod_hooks));
	unregister_net_sysctl_table(an->sysctl);
	kfree(an->table);
	aod_apply(net, an, AOD_EMU_OFF);
}

static struct pernet_operations aod_net_ops = {
	.init = aod_net_init,
	.exit = aod_net_exit,
	.id = &aod_net_id,
	.size = sizeof(struct aod_net),
};

static int __init
aod_init(void)
{
	return (register_pernet_subsys(&aod_net_ops));
}

static void __exit
aod_exit(void)
{
	unregister_pernet_subsys(&aod_net_ops);
}

module_init(aod_init);
module_exit(aod_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("aod: Anti OS Detection, per network namespace");
