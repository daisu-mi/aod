/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Daisuke Miyamoto
 *
 * aod-kld: Anti OS Detection, pfil KLD port for modern FreeBSD.
 * Lineage: daisu-mi/aod (2001, FreeBSD 4.3 kernel patch).
 * Research/defensive use. Run in an isolated VM.
 *
 * Written against FreeBSD release/15.1.0 (PFIL_VERSION 2).
 *
 * Everything is done from two pfil hooks on the IPv4 head.  No kernel
 * source is changed.
 *
 *   out: TTL, DF, IP id, window and option order on SYN and SYN|ACK,
 *        ack field of bare RST, ICMP echo reply code
 *   in:  replies to odd-flag probes, ECN stripping
 *
 * ISS translation is not here yet.  Only the default vnet is hooked.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/epoch.h>
#include <sys/module.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/libkern.h>

#include <machine/atomic.h>
#include <machine/in_cksum.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/pfil.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>

#include "aod.h"

/* defined in tcp_subr.c; tcp_var.h has the V_ macro but no declaration */
VNET_DECLARE(int, tcp_ts_offset_per_conn);

#define	AOD_WIN4(w)	{ { (w), (w) }, { (w), (w) } }

/*
 * 1 to 5: values from the last 2001 version (src/netinet in daisu-mi/aod).
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
		.null_reply = AOD_NULL_RSTACK,
		.synfin_reply = AOD_SYNFIN_RSTACK, .rst_noack = 1,
		.rst_ack_other = 1, .echo_code0 = 1,
	},
	[AOD_EMU_WIN11_NOTS] = {
		.kind = AOD_EMU_WIN11_NOTS,
		.synack_win = { { 0xff70, 0xffff }, { 0xffdc, 0xffff } },
		.syn_win = 0xfaf0,
		.ttl = 128, .icmp_ttl = 128,
		.ipid_stride = 1,
		.opt_order = AOD_OPT_WINDOWS, .wscale = 8,
		.no_ecn = 1, .strip_ts = 1,
		.null_reply = AOD_NULL_RSTACK,
		.synfin_reply = AOD_SYNFIN_RSTACK, .rst_noack = 1,
		.rst_ack_other = 1, .echo_code0 = 1,
	},
};

static int aod_kind = AOD_EMU_OFF;
static volatile u_int aod_ipid;		/* next IP id, host byte order */
static pfil_hook_t aod_out_hook, aod_in_hook;
static int aod_saved_ts_per_conn = -1;	/* -1: not touched */

/*
 * The kernel gives every connection its own timestamp offset by default.
 * Linux and Windows keep one clock per peer, and nmap measures that.
 */
static void
aod_apply_ts(const struct aod_profile *p)
{

	CURVNET_SET(vnet0);
	if (p->ts_per_host) {
		if (aod_saved_ts_per_conn < 0)
			aod_saved_ts_per_conn = V_tcp_ts_offset_per_conn;
		V_tcp_ts_offset_per_conn = 0;
	} else if (aod_saved_ts_per_conn >= 0) {
		V_tcp_ts_offset_per_conn = aod_saved_ts_per_conn;
		aod_saved_ts_per_conn = -1;
	}
	CURVNET_RESTORE();
}

static int
aod_sysctl_kind(SYSCTL_HANDLER_ARGS)
{
	int error, new;

	new = aod_kind;
	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (new < AOD_EMU_OFF || new > AOD_EMU_MAX)
		return (EINVAL);
	aod_apply_ts(&aod_profiles[new]);
	aod_kind = new;
	return (0);
}

/* Same name as the 2001 version: net.inet.tcp.emu_kind */
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, emu_kind,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0, aod_sysctl_kind, "I",
    "Emulate another kind of tcp stacks (0 off, 1 FreeBSD, 2 NetBSD, "
    "3 Windows, 4 Windows 2000, 5 Cisco, 6 Linux 6, 7 Windows 11, "
    "8 Windows 11 without timestamps)");

/* RFC 1624 incremental update. All values in network byte order. */
static uint16_t
aod_cksum_fixup(uint16_t cksum, uint16_t old, uint16_t new)
{
	uint32_t x;

	x = (uint16_t)~cksum + (uint16_t)~old + new;
	x = (x >> 16) + (x & 0xffff);
	x += x >> 16;
	return ((uint16_t)~x);
}

/* Replace len bytes (even, 16 bit aligned in the packet) and fix cksum. */
static void
aod_replace(uint8_t *dst, const uint8_t *src, int len, uint16_t *cksum)
{
	uint16_t o, n;
	int i;

	for (i = 0; i + 1 < len; i += 2) {
		memcpy(&o, dst + i, 2);
		memcpy(&n, src + i, 2);
		if (o == n)
			continue;
		memcpy(dst + i, &n, 2);
		if (cksum != NULL)
			*cksum = aod_cksum_fixup(*cksum, o, n);
	}
}

static uint16_t
aod_next_ipid(const struct aod_profile *p, bool syn)
{
	u_int stride, id;

	stride = p->ipid_stride;
	if (syn && p->ipid_zero_on_syn) {
		atomic_store_int(&aod_ipid, stride);
		return (0);
	}
	do {
		id = atomic_fetchadd_int(&aod_ipid, stride);
		if (stride > 1)
			id -= id % stride;
	} while (stride == 1 && (uint16_t)id == 0);	/* 0 means "not set" */
	return ((uint16_t)id);
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
		if (opt == TCPOPT_MAXSEG && optlen == TCPOLEN_MAXSEG) {
			o->mss = true;
			memcpy(o->mssval, cp + 2, 2);
		} else if (opt == TCPOPT_WINDOW && optlen == TCPOLEN_WINDOW) {
			o->ws = true;
			o->wsval = cp[2];
		} else if (opt == TCPOPT_SACK_PERMITTED &&
		    optlen == TCPOLEN_SACK_PERMITTED) {
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

	*cp++ = TCPOPT_MAXSEG;
	*cp++ = TCPOLEN_MAXSEG;
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
			*cp++ = TCPOPT_SACK_PERMITTED;
			*cp++ = TCPOLEN_SACK_PERMITTED;
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
			*cp++ = TCPOPT_SACK_PERMITTED;
			*cp++ = TCPOLEN_SACK_PERMITTED;
		}
	}
	return (cp - buf);
}

/*
 * Outbound TCP.  The TCP checksum is either still pending (CSUM_TCP set,
 * th_sum holds the pseudo header sum only, which covers neither the
 * header fields nor the options) or already final, in which case it is
 * fixed up.
 */
static void
aod_out_tcp(const struct aod_profile *p, struct mbuf *m, struct ip *ip,
    int hlen)
{
	int newlen, tcplen;
	struct aod_opts o;
	struct tcphdr *th;
	uint8_t buf[TCP_MAXOLEN], *optp;
	uint16_t *sump, win, new16;
	uint32_t ack;
	uint8_t thflags;
	int optlen;

	if (m->m_len < hlen + (int)sizeof(struct tcphdr))
		return;
	th = (struct tcphdr *)((char *)ip + hlen);
	thflags = tcp_get_flags(th) & (TH_SYN | TH_ACK | TH_FIN | TH_RST);
	sump = (m->m_pkthdr.csum_flags & CSUM_TCP) != 0 ? NULL : &th->th_sum;

	if (p->set_df == AOD_DF_ON)
		ip->ip_off |= htons(IP_DF);
	else if (p->set_df == AOD_DF_OFF)
		ip->ip_off &= ~htons(IP_DF);

	/* T4 and T6 of nmap: Windows leaves something in the ack field */
	if (p->rst_ack_other && thflags == TH_RST && th->th_ack == 0) {
		ack = arc4random() | htonl(0x00010000);
		aod_replace((uint8_t *)&th->th_ack, (uint8_t *)&ack, 4, sump);
	}

	if ((thflags & TH_SYN) == 0 || (thflags & (TH_FIN | TH_RST)) != 0)
		return;

	memset(&o, 0, sizeof(o));
	optlen = (th->th_off << 2) - (int)sizeof(struct tcphdr);
	optp = (uint8_t *)(th + 1);
	if (optlen > 0 && optlen <= TCP_MAXOLEN &&
	    m->m_len >= hlen + (th->th_off << 2)) {
		aod_opts_parse(optp, optlen, &o);
		if (p->opt_order != AOD_OPT_LEAVE && o.mss && !o.other) {
			/* a smaller shift only makes the peer see less room */
			if (o.ws && p->wscale != 0 && p->wscale < o.wsval)
				o.wsval = p->wscale;
			/* our own SYN goes out without the timestamp */
			if (p->strip_ts && (thflags & TH_ACK) == 0)
				o.ts = false;
			memset(buf, 0, sizeof(buf));
			newlen = aod_opts_emit(p->opt_order, &o, buf);
			tcplen = (int)sizeof(struct tcphdr) + optlen;
			if (newlen == optlen)
				aod_replace(optp, buf, optlen, sump);
			else if (newlen < optlen && (newlen & 3) == 0 &&
			    sump == NULL && m->m_next == NULL &&
			    m->m_len == hlen + tcplen &&
			    ntohs(ip->ip_len) == hlen + tcplen) {
				/*
				 * Shorter options on a segment without data:
				 * cut the tail.  The checksum is still
				 * pending, so only the pseudo header sum has
				 * to follow the new length.
				 */
				memcpy(optp, buf, newlen);
				tcplen = (int)sizeof(struct tcphdr) + newlen;
				th->th_off = tcplen >> 2;
				m->m_len = m->m_pkthdr.len = hlen + tcplen;
				ip->ip_len = htons(hlen + tcplen);
				th->th_sum = in_pseudo(ip->ip_src.s_addr,
				    ip->ip_dst.s_addr,
				    htons(IPPROTO_TCP + tcplen));
			}
		}
	}

	win = (thflags & TH_ACK) != 0 ? p->synack_win[o.ts][o.ws] : p->syn_win;
	if (win != 0) {
		new16 = htons(win);
		aod_replace((uint8_t *)&th->th_win, (uint8_t *)&new16, 2,
		    sump);
	}
}

static void
aod_out_icmp(const struct aod_profile *p, struct mbuf *m, struct ip *ip,
    int hlen)
{
	struct icmp *icp;
	uint16_t old, new;

	if (!p->echo_code0 || m->m_len < hlen + ICMP_MINLEN)
		return;
	icp = (struct icmp *)((char *)ip + hlen);
	if (icp->icmp_type != ICMP_ECHOREPLY || icp->icmp_code == 0)
		return;
	memcpy(&old, icp, 2);
	icp->icmp_code = 0;
	memcpy(&new, icp, 2);
	icp->icmp_cksum = aod_cksum_fixup(icp->icmp_cksum, old, new);
}

/*
 * Outbound hook.  ip_output() computes the IP header checksum after the
 * pfil hooks have run, so IP header fields can be changed freely here.
 */
static pfil_return_t
aod_check_out(struct mbuf **mp, struct ifnet *ifp __unused, int flags,
    void *ruleset __unused, struct inpcb *inp __unused)
{
	const struct aod_profile *p;
	struct mbuf *m;
	struct ip *ip;
	uint16_t thflags;
	uint8_t ttl;
	bool syn, setid;
	int kind, hlen;

	kind = aod_kind;
	if (kind <= AOD_EMU_FREEBSD || kind > AOD_EMU_MAX)
		return (PFIL_PASS);
	if (flags & PFIL_FWD)		/* local packets only */
		return (PFIL_PASS);
	p = &aod_profiles[kind];

	m = *mp;
	if (m->m_len < (int)sizeof(struct ip) || !M_WRITABLE(m))
		return (PFIL_PASS);
	ip = mtod(m, struct ip *);
	hlen = ip->ip_hl << 2;
	if (ip->ip_v != IPVERSION || hlen < (int)sizeof(struct ip) ||
	    m->m_len < hlen)
		return (PFIL_PASS);
	/* leave fragments and TSO bursts alone */
	if ((ip->ip_off & htons(IP_MF | IP_OFFMASK)) != 0 ||
	    (m->m_pkthdr.csum_flags & CSUM_TSO) != 0)
		return (PFIL_PASS);

	/* TTL: only when the sender left the system default */
	ttl = ip->ip_p == IPPROTO_ICMP ? p->icmp_ttl : p->ttl;
	if (ttl != 0 && ip->ip_ttl == V_ip_defttl)
		ip->ip_ttl = ttl;

	syn = false;
	setid = p->ipid_stride != 0 && !p->ipid_tcp_only;
	if (ip->ip_p == IPPROTO_TCP) {
		aod_out_tcp(p, m, ip, hlen);
		if (m->m_len >= hlen + (int)sizeof(struct tcphdr)) {
			thflags = tcp_get_flags((struct tcphdr *)((char *)ip +
			    hlen));
			syn = (thflags & TH_SYN) != 0;
			if (p->ipid_tcp_only)
				setid = (thflags & TH_RST) == 0 &&
				    (thflags & (TH_SYN | TH_ACK)) !=
				    (TH_SYN | TH_ACK);
		}
	} else if (ip->ip_p == IPPROTO_ICMP)
		aod_out_icmp(p, m, ip, hlen);

	if (setid)
		ip->ip_id = htons(aod_next_ipid(p, syn));

	return (PFIL_PASS);
}

/*
 * Send a bare TCP segment back to the sender of (oip, oth).
 * seq and ack are in network byte order.
 */
static void
aod_tcp_reply(const struct ip *oip, const struct tcphdr *oth, uint32_t seq,
    uint32_t ack, uint8_t thflags)
{
	struct mbuf *m;
	struct ip *ip;
	struct tcphdr *th;
	int len;

	len = sizeof(struct ip) + sizeof(struct tcphdr);
	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (m == NULL)
		return;
	m->m_data += max_linkhdr;
	m->m_len = m->m_pkthdr.len = len;
	ip = mtod(m, struct ip *);
	memset(ip, 0, len);
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_len = htons(len);
	ip->ip_off = htons(IP_DF);
	ip->ip_ttl = V_ip_defttl;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_src = oip->ip_dst;
	ip->ip_dst = oip->ip_src;
	th = (struct tcphdr *)(ip + 1);
	th->th_sport = oth->th_dport;
	th->th_dport = oth->th_sport;
	th->th_seq = seq;
	th->th_ack = ack;
	th->th_off = sizeof(struct tcphdr) >> 2;
	tcp_set_flags(th, thflags);
	th->th_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
	    htons(IPPROTO_TCP + sizeof(struct tcphdr)));
	m->m_pkthdr.csum_flags = CSUM_TCP;
	m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
	(void)ip_output(m, NULL, NULL, 0, NULL, NULL);
}

/* Overwrite the timestamp option of an inbound segment with NOPs. */
static void
aod_in_strip_ts(struct mbuf *m, struct tcphdr *th, int hlen)
{
	static const uint8_t nops[TCPOLEN_TIMESTAMP] = {
		TCPOPT_NOP, TCPOPT_NOP, TCPOPT_NOP, TCPOPT_NOP, TCPOPT_NOP,
		TCPOPT_NOP, TCPOPT_NOP, TCPOPT_NOP, TCPOPT_NOP, TCPOPT_NOP
	};
	uint8_t buf[TCP_MAXOLEN], *cp;
	int len, optlen, i;

	len = (th->th_off << 2) - (int)sizeof(struct tcphdr);
	if (len <= 0 || len > TCP_MAXOLEN || m->m_len < hlen + (th->th_off << 2))
		return;
	cp = (uint8_t *)(th + 1);
	memcpy(buf, cp, len);
	for (i = 0; i < len; i += optlen) {
		if (buf[i] == TCPOPT_EOL)
			break;
		if (buf[i] == TCPOPT_NOP) {
			optlen = 1;
			continue;
		}
		if (i + 1 >= len || (optlen = buf[i + 1]) < 2 ||
		    i + optlen > len)
			return;
		if (buf[i] == TCPOPT_TIMESTAMP && optlen == TCPOLEN_TIMESTAMP)
			memcpy(buf + i, nops, TCPOLEN_TIMESTAMP);
	}
	aod_replace(cp, buf, len, &th->th_sum);
}

/*
 * Inbound hook.  The packet still carries the checksum from the wire.
 */
static pfil_return_t
aod_check_in(struct mbuf **mp, struct ifnet *ifp __unused,
    int flags __unused, void *ruleset __unused, struct inpcb *inp __unused)
{
	const struct aod_profile *p;
	struct mbuf *m;
	struct ip *ip;
	struct tcphdr *th;
	uint16_t old, new;
	uint8_t thflags;
	int kind, hlen;

	kind = aod_kind;
	if (kind <= AOD_EMU_FREEBSD || kind > AOD_EMU_MAX)
		return (PFIL_PASS);
	p = &aod_profiles[kind];

	m = *mp;
	if (m->m_len < (int)sizeof(struct ip))
		return (PFIL_PASS);
	ip = mtod(m, struct ip *);
	hlen = ip->ip_hl << 2;
	if (ip->ip_v != IPVERSION || ip->ip_p != IPPROTO_TCP ||
	    hlen < (int)sizeof(struct ip) ||
	    (ip->ip_off & htons(IP_MF | IP_OFFMASK)) != 0 ||
	    m->m_len < hlen + (int)sizeof(struct tcphdr))
		return (PFIL_PASS);
	/* only what is addressed to this host */
	if (m->m_flags & (M_BCAST | M_MCAST) ||
	    !in_localip(ip->ip_dst))
		return (PFIL_PASS);
	th = (struct tcphdr *)((char *)ip + hlen);
	thflags = tcp_get_flags(th) & 0xff;

	if ((thflags & (TH_SYN | TH_FIN | TH_RST | TH_ACK | TH_PUSH |
	    TH_URG)) == 0 && p->null_reply != AOD_NULL_LEAVE) {
		aod_tcp_reply(ip, th,
		    p->null_reply == AOD_NULL_RSTACK_SEQ ? th->th_ack : 0,
		    th->th_seq, TH_RST | TH_ACK);
		goto drop;
	}

	/*
	 * FIN, PSH or URG with none of SYN, RST and ACK: some stacks reset
	 * these even on a listening port, which makes FIN and Xmas scans
	 * report every port as closed.
	 */
	if (p->rst_noack && (thflags & (TH_SYN | TH_RST | TH_ACK)) == 0) {
		int tlen;

		tlen = (int)ntohs(ip->ip_len) - hlen - (th->th_off << 2);
		if (tlen < 0)
			tlen = 0;
		if (thflags & TH_FIN)
			tlen++;
		aod_tcp_reply(ip, th, 0, htonl(ntohl(th->th_seq) + tlen),
		    TH_RST | TH_ACK);
		goto drop;
	}

	if ((thflags & (TH_SYN | TH_FIN | TH_RST | TH_ACK)) ==
	    (TH_SYN | TH_FIN)) {
		if (p->synfin_reply == AOD_SYNFIN_RSTACK)
			aod_tcp_reply(ip, th, 0,
			    htonl(ntohl(th->th_seq) + 2), TH_RST | TH_ACK);
		if (p->synfin_reply != AOD_SYNFIN_LEAVE)
			goto drop;
	}

	/* hide the ECN request so that the kernel never agrees to it */
	if (p->no_ecn && (thflags & (TH_SYN | TH_ACK | TH_RST)) == TH_SYN &&
	    (thflags & (TH_ECE | TH_CWR)) != 0 && M_WRITABLE(m)) {
		memcpy(&old, (char *)th + 12, 2);
		tcp_set_flags(th, tcp_get_flags(th) & ~(TH_ECE | TH_CWR));
		memcpy(&new, (char *)th + 12, 2);
		th->th_sum = aod_cksum_fixup(th->th_sum, old, new);
	}

	/* blank the timestamp offer so that the kernel never uses it */
	if (p->strip_ts && (thflags & (TH_SYN | TH_ACK | TH_RST)) == TH_SYN &&
	    M_WRITABLE(m))
		aod_in_strip_ts(m, th, hlen);
	return (PFIL_PASS);

drop:
	m_freem(m);
	*mp = NULL;
	return (PFIL_DROPPED);
}

static int
aod_hook_one(pfil_hook_t *hookp, pfil_mbuf_chk_t fn, int dir,
    const char *name)
{
	struct pfil_hook_args pha = {
		.pa_version = PFIL_VERSION,
		.pa_modname = "aod",
		.pa_type = PFIL_TYPE_IP4,
		.pa_mbuf_chk = fn,
		.pa_flags = dir,
		.pa_rulname = name,
	};
	struct pfil_link_args pla = {
		.pa_version = PFIL_VERSION,
		.pa_flags = dir | PFIL_HEADPTR | PFIL_HOOKPTR,
	};
	int error;

	*hookp = pfil_add_hook(&pha);
	pla.pa_head = V_inet_pfil_head;
	pla.pa_hook = *hookp;
	error = pfil_link(&pla);
	if (error != 0) {
		pfil_remove_hook(*hookp);
		*hookp = NULL;
	}
	return (error);
}

static void
aod_unhook(void)
{

	aod_kind = AOD_EMU_OFF;
	aod_apply_ts(&aod_profiles[AOD_EMU_OFF]);
	CURVNET_SET(vnet0);
	if (aod_in_hook != NULL)
		pfil_remove_hook(aod_in_hook);
	if (aod_out_hook != NULL)
		pfil_remove_hook(aod_out_hook);
	aod_in_hook = aod_out_hook = NULL;
	CURVNET_RESTORE();
	/* let packets still inside the hooks finish before the code goes away */
	NET_EPOCH_WAIT();
}

static int
aod_hook(void)
{
	int error;

	CURVNET_SET(vnet0);
	error = aod_hook_one(&aod_out_hook, aod_check_out, PFIL_OUT,
	    "default-out");
	if (error == 0)
		error = aod_hook_one(&aod_in_hook, aod_check_in, PFIL_IN,
		    "default-in");
	CURVNET_RESTORE();
	if (error != 0)
		aod_unhook();
	return (error);
}

static int
aod_modevent(module_t mod __unused, int type, void *data __unused)
{

	switch (type) {
	case MOD_LOAD:
		atomic_store_int(&aod_ipid, arc4random());
		return (aod_hook());
	case MOD_UNLOAD:
		aod_unhook();
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t aod_mod = {
	"aod",
	aod_modevent,
	NULL
};

DECLARE_MODULE(aod, aod_mod, SI_SUB_PROTO_FIREWALL, SI_ORDER_ANY);
MODULE_VERSION(aod, 1);
