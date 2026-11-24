/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Daisuke Miyamoto
 *
 * aod-kld: Anti OS Detection, pfil KLD port for modern FreeBSD.
 * Lineage: daisu-mi/aod (2001, FreeBSD 4.3 kernel patch).
 * Research/defensive use. Run in an isolated VM.
 */
#ifndef _AOD_H_
#define _AOD_H_

/* emulation personalities (kept compatible with 2001 aod constants) */
#define	AOD_EMU_OFF	0x00
#define	AOD_EMU_FREEBSD	0x01
#define	AOD_EMU_NETBSD	0x02
#define	AOD_EMU_WINDOWS	0x03
#define	AOD_EMU_WIN2K	0x04
#define	AOD_EMU_CISCO	0x05
#define	AOD_EMU_LINUX	0x06	/* Linux 6.0 in nmap-os-db */
#define	AOD_EMU_LINUX7	0x07	/* Ubuntu 26.04.1 (Linux 7.0) as measured */
#define	AOD_EMU_WIN11	0x08	/* Windows 11; agrees with nmap-os-db and a real host */
#define	AOD_EMU_MAX	AOD_EMU_WIN11

/* set_df values */
#define	AOD_DF_LEAVE	0
#define	AOD_DF_ON	1
#define	AOD_DF_OFF	2

/* order of the TCP options on SYN and SYN|ACK */
#define	AOD_OPT_LEAVE	0
#define	AOD_OPT_LINUX	1	/* MSS, SACK, TS, NOP, WS */
#define	AOD_OPT_WINDOWS	2	/* MSS, NOP, WS, SACK, TS */

/* reply to a TCP segment with no flags */
#define	AOD_NULL_LEAVE	0
#define	AOD_NULL_RSTACK	1	/* RST|ACK, seq 0, ack = their seq */
#define	AOD_NULL_RSTACK_SEQ 2	/* RST|ACK, seq = their ack, ack = their seq */

/* reply to SYN|FIN */
#define	AOD_SYNFIN_LEAVE 0
#define	AOD_SYNFIN_DROP	1
#define	AOD_SYNFIN_RSTACK 2	/* RST|ACK, seq 0, ack = their seq + 2 */

/* per-personality TCP/IP profile used by the pfil hooks */
struct aod_profile {
	int		kind;
	/* window on SYN|ACK, indexed [has timestamp][has window scale] */
	uint16_t	synack_win[2][2];
	/* the same over IPv6; all 0 = use synack_win */
	uint16_t	synack_win6[2][2];
	uint16_t	syn_win;	/* advertised window on SYN, 0 = leave */
	uint8_t		ttl;		/* IP TTL except ICMP, 0 = leave */
	uint8_t		icmp_ttl;	/* IP TTL for ICMP, 0 = leave */
	uint8_t		set_df;		/* AOD_DF_* for TCP */
	uint16_t	ipid_stride;	/* IP id increment, 0 = leave kernel default */
	uint8_t		ipid_zero_on_syn; /* restart the IP id counter at 0 on SYN */
	uint8_t		ipid_tcp_only;	/* count only on TCP other than SYN|ACK and RST */
	uint8_t		strip_ts;	/* never offer TCP timestamps on our own SYN */
	uint8_t		refuse_ts;	/* never accept TCP timestamps offered to us */
	uint8_t		opt_order;	/* AOD_OPT_* */
	uint8_t		wscale;		/* window scale to announce, 0 = leave */
	uint8_t		no_ecn;		/* never negotiate ECN */
	uint8_t		ts_per_host;	/* one timestamp clock per peer host */
	uint8_t		null_reply;	/* AOD_NULL_* */
	uint8_t		synfin_reply;	/* AOD_SYNFIN_* */
	uint8_t		rst_noack;	/* RST|ACK to FIN, PSH or URG without ACK, open port or not */
	uint8_t		rst_ack_other;	/* nonzero ack field on RST without ACK */
	uint8_t		rst_ack_seq6;	/* over IPv6 that field repeats the seq field */
	uint8_t		echo_code0;	/* ICMP echo reply always has code 0 */
	/* IPv6: a solicited neighbor advertisement always has the override
	 * flag and the target link-layer address option */
	uint8_t		na_lladdr;
};

#endif /* _AOD_H_ */
