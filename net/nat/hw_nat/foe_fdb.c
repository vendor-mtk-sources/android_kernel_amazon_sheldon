/******************************************************************************
 *
 * This file is provided under a dual license.  When you use or
 * distribute this software, you may choose to be licensed under
 * version 2 of the GNU General Public License ("GPLv2 License")
 * or BSD License.
 *
 * GPLv2 License
 *
 * Copyright(C) 2017 MediaTek Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See http://www.gnu.org/licenses/gpl-2.0.html for more details.
 *
 * BSD LICENSE
 *
 * Copyright(C) 2017 MediaTek Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/ra_nat.h>

#include "frame_engine.h"
#include "foe_fdb.h"
#include "hwnat_ioctl.h"
#include "util.h"
#include "api.h"
#include "hwnat_config.h"
#include "hwnat_define.h"

struct pkt_rx_parse_result ppe_parse_rx_result;

#define DD \
{\
pr_info("%s %d\n", __func__, __LINE__); \
}

/* 4          2         0 */
/* +----------+---------+ */
/* |      DMAC[47:16]   | */
/* +--------------------+ */
/* |DMAC[15:0]| 2nd VID | */
/* +----------+---------+ */
/* 4          2         0 */
/* +----------+---------+ */
/* |      SMAC[47:16]   | */
/* +--------------------+ */
/* |SMAC[15:0]| PPPOE ID| */
/* +----------+---------+ */
/* Ex: */
/* Mac=01:22:33:44:55:66 */
/* 4          2         0 */
/* +----------+---------+ */
/* |     01:22:33:44    | */
/* +--------------------+ */
/* |  55:66   | PPPOE ID| */
/* +----------+---------+ */
void foe_set_mac_hi_info(u8 *dst, uint8_t *src)
{
	dst[3] = src[0];
	dst[2] = src[1];
	dst[1] = src[2];
	dst[0] = src[3];
}

void foe_set_mac_lo_info(u8 *dst, uint8_t *src)
{
	dst[1] = src[4];
	dst[0] = src[5];
}

static int is_request_done(void)
{
	int count = 1000;

	/* waiting for 1sec to make sure action was finished */
	do {
		if (((reg_read(CAH_CTRL) >> 8) & 0x1) == 0)
			return 1;
		usleep_range(1000, 1100);
	} while (--count);

	return 0;
}

#define MAX_CACHE_LINE_NUM		32
int foe_dump_cache_entry(void)
{
	int line = 0;
	int state = 0;
	int tag = 0;
	int cah_en = 0;
	int i = 0;

	cah_en = reg_read(CAH_CTRL) & 0x1;

	if (!cah_en) {
		pr_debug("Cache is not enabled\n");
		return 0;
	}

	/* cache disable */
	reg_modify_bits(CAH_CTRL, 0, 0, 1);

	pr_debug(" No--|---State---|----Tag-----\n");
	pr_debug("-----+-----------+------------\n");
	for (line = 0; line < MAX_CACHE_LINE_NUM; line++) {
		/* set line number */
		reg_modify_bits(CAH_LINE_RW, line, 0, 15);

		/* OFFSET_RW = 0x1F (Get Entry Number) */
		reg_modify_bits(CAH_LINE_RW, 0x1F, 16, 8);

		/* software access cache command = read */
		reg_modify_bits(CAH_CTRL, 2, 12, 2);

		/* trigger software access cache request */
		reg_modify_bits(CAH_CTRL, 1, 8, 1);

		if (is_request_done()) {
			tag = (reg_read(CAH_RDATA) & 0xFFFF);
			state = ((reg_read(CAH_RDATA) >> 16) & 0x3);
			pr_debug("%04d | %s   | %05d\n", line,
				 (state == 3) ? " Lock  " :
				 (state == 2) ? " Dirty " :
				 (state == 1) ? " Valid " : "Invalid", tag);
		} else {
			pr_debug("%s is timeout (%d)\n", __func__, line);
		}

		/* software access cache command = read */
		reg_modify_bits(CAH_CTRL, 3, 12, 2);

		reg_write(CAH_WDATA, 0);

		/* trigger software access cache request */
		reg_modify_bits(CAH_CTRL, 1, 8, 1);

		if (!is_request_done())
			pr_debug("%s is timeout (%d)\n", __func__, line);
		/* dump first 16B for each foe entry */
		pr_debug("==========<Flow Table Entry=%d >===============\n", tag);
		for (i = 0; i < 16; i++) {
			reg_modify_bits(CAH_LINE_RW, i, 16, 8);

			/* software access cache command = read */
			reg_modify_bits(CAH_CTRL, 2, 12, 2);

			/* trigger software access cache request */
			reg_modify_bits(CAH_CTRL, 1, 8, 1);

			if (is_request_done())
				pr_debug("%02d  %08X\n", i, reg_read(CAH_RDATA));
			else
				pr_debug("%s is timeout (%d)\n", __func__, line);

			/* software access cache command = write */
			reg_modify_bits(CAH_CTRL, 3, 12, 2);

			reg_write(CAH_WDATA, 0);

			/* trigger software access cache request */
			reg_modify_bits(CAH_CTRL, 1, 8, 1);

			if (!is_request_done())
				pr_debug("%s is timeout (%d)\n", __func__, line);
		}
		pr_debug("=========================================\n");
	}

	/* clear cache table before enabling cache */
	reg_modify_bits(CAH_CTRL, 1, 9, 1);
	reg_modify_bits(CAH_CTRL, 0, 9, 1);

	/* cache enable */
	reg_modify_bits(CAH_CTRL, 1, 0, 1);

	return 1;
}

void foe_dump_entry(uint32_t index)
{
	struct foe_entry *entry = &ppe_foe_base[index];
	struct ps_entry *ps_entry = &ppe_ps_base[index];

	u32 *p = (uint32_t *)entry;
	u32 i = 0;
	u32 print_cnt;

	NAT_PRINT("==========<Flow Table Entry=%d (%p)>===============\n", index, entry);
	if (debug_level >= 2) {
		if (fe_feature & HNAT_IPV6)
			print_cnt = 20;
		else
			print_cnt = 16;

		for (i = 0; i < print_cnt; i++)
			NAT_PRINT("%02d: %08X\n", i, *(p + i));
	}
	NAT_PRINT("-----------------<Flow Info>------------------\n");
	NAT_PRINT("Information Block 1: %08X\n", entry->ipv4_hnapt.info_blk1);

	if (IS_IPV4_HNAPT(entry)) {
		NAT_PRINT("Information Block 2=%x (FP=%d FQOS=%d QID=%d)",
			  entry->ipv4_hnapt.info_blk2,
			  entry->ipv4_hnapt.info_blk2 >> 5 & 0x7,
			  entry->ipv4_hnapt.info_blk2 >> 4 & 0x1,
			  (entry->ipv4_hnapt.iblk2.qid) +
			  ((entry->ipv4_hnapt.iblk2.qid1 & 0x03) << 4));
		if (hnat_chip_name & MT7622_HWNAT) {
			NAT_PRINT("Information Block 2=%x (FP=%d FQOS=%d QID=%d)",
				  entry->ipv4_hnapt.info_blk2,
				  entry->ipv4_hnapt.info_blk2 >> 5 & 0x7,
				  entry->ipv4_hnapt.info_blk2 >> 4 & 0x1,
				  (entry->ipv4_hnapt.iblk2.qid) +
				  ((entry->ipv4_hnapt.iblk2.qid1 & 0x03) << 4));
		} else {
			NAT_PRINT("Information Block 2=%x (FP=%d FQOS=%d QID=%d)",
				  entry->ipv4_hnapt.info_blk2,
				  entry->ipv4_hnapt.info_blk2 >> 5 & 0x7,
				  entry->ipv4_hnapt.info_blk2 >> 4 & 0x1,
				  entry->ipv4_hnapt.iblk2.qid);
		}
		NAT_PRINT("Create IPv4 HNAPT entry\n");
		NAT_PRINT
		    ("IPv4 Org IP/Port: %u.%u.%u.%u:%d->%u.%u.%u.%u:%d\n",
		     IP_FORMAT3(entry->ipv4_hnapt.sip), IP_FORMAT2(entry->ipv4_hnapt.sip),
		     IP_FORMAT1(entry->ipv4_hnapt.sip), IP_FORMAT0(entry->ipv4_hnapt.sip),
		     entry->ipv4_hnapt.sport,
		     IP_FORMAT3(entry->ipv4_hnapt.dip), IP_FORMAT2(entry->ipv4_hnapt.dip),
		     IP_FORMAT1(entry->ipv4_hnapt.dip), IP_FORMAT0(entry->ipv4_hnapt.dip),
		     entry->ipv4_hnapt.dport);
		NAT_PRINT
		    ("IPv4 New IP/Port: %u.%u.%u.%u:%d->%u.%u.%u.%u:%d\n",
		     IP_FORMAT3(entry->ipv4_hnapt.new_sip), IP_FORMAT2(entry->ipv4_hnapt.new_sip),
		     IP_FORMAT1(entry->ipv4_hnapt.new_sip), IP_FORMAT0(entry->ipv4_hnapt.new_sip),
		     entry->ipv4_hnapt.new_sport,
		     IP_FORMAT3(entry->ipv4_hnapt.new_dip), IP_FORMAT2(entry->ipv4_hnapt.new_dip),
		     IP_FORMAT1(entry->ipv4_hnapt.new_dip), IP_FORMAT0(entry->ipv4_hnapt.new_dip),
		     entry->ipv4_hnapt.new_dport);
	} else if (IS_IPV4_HNAT(entry)) {
		NAT_PRINT("Information Block 2: %08X\n", entry->ipv4_hnapt.info_blk2);
		NAT_PRINT("Create IPv4 HNAT entry\n");
		NAT_PRINT("IPv4 Org IP: %u.%u.%u.%u->%u.%u.%u.%u\n",
			  IP_FORMAT3(entry->ipv4_hnapt.sip), IP_FORMAT2(entry->ipv4_hnapt.sip),
			  IP_FORMAT1(entry->ipv4_hnapt.sip), IP_FORMAT0(entry->ipv4_hnapt.sip),
			  IP_FORMAT3(entry->ipv4_hnapt.dip), IP_FORMAT2(entry->ipv4_hnapt.dip),
			  IP_FORMAT1(entry->ipv4_hnapt.dip), IP_FORMAT0(entry->ipv4_hnapt.dip));
		NAT_PRINT("IPv4 New IP: %u.%u.%u.%u->%u.%u.%u.%u\n",
			  IP_FORMAT3(entry->ipv4_hnapt.new_sip), IP_FORMAT2(entry->ipv4_hnapt.new_sip),
			  IP_FORMAT1(entry->ipv4_hnapt.new_sip), IP_FORMAT0(entry->ipv4_hnapt.new_sip),
			  IP_FORMAT3(entry->ipv4_hnapt.new_dip), IP_FORMAT2(entry->ipv4_hnapt.new_dip),
			  IP_FORMAT1(entry->ipv4_hnapt.new_dip), IP_FORMAT0(entry->ipv4_hnapt.new_dip));
	}
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV6_1T_ROUTE(entry)) {
			NAT_PRINT("Information Block 2: %08X\n", entry->ipv6_1t_route.info_blk2);
			NAT_PRINT("Create IPv6 Route entry\n");
			NAT_PRINT("Destination IPv6: %08X:%08X:%08X:%08X",
				  entry->ipv6_1t_route.ipv6_dip3, entry->ipv6_1t_route.ipv6_dip2,
				  entry->ipv6_1t_route.ipv6_dip1, entry->ipv6_1t_route.ipv6_dip0);
		} else if (IS_IPV4_DSLITE(entry)) {
			NAT_PRINT("Information Block 2: %08X\n", entry->ipv4_dslite.info_blk2);
			NAT_PRINT("Create IPv4 Ds-Lite entry\n");
			NAT_PRINT
			    ("IPv4 Ds-Lite: %u.%u.%u.%u.%d->%u.%u.%u.%u:%d\n ",
			     IP_FORMAT3(entry->ipv4_dslite.sip), IP_FORMAT2(entry->ipv4_dslite.sip),
			     IP_FORMAT1(entry->ipv4_dslite.sip), IP_FORMAT0(entry->ipv4_dslite.sip),
			     entry->ipv4_dslite.sport,
			     IP_FORMAT3(entry->ipv4_dslite.dip), IP_FORMAT2(entry->ipv4_dslite.dip),
			     IP_FORMAT1(entry->ipv4_dslite.dip), IP_FORMAT0(entry->ipv4_dslite.dip),
			     entry->ipv4_dslite.dport);
			NAT_PRINT("EG DIPv6: %08X:%08X:%08X:%08X->%08X:%08X:%08X:%08X\n",
				  entry->ipv4_dslite.tunnel_sipv6_0, entry->ipv4_dslite.tunnel_sipv6_1,
				  entry->ipv4_dslite.tunnel_sipv6_2, entry->ipv4_dslite.tunnel_sipv6_3,
				  entry->ipv4_dslite.tunnel_dipv6_0, entry->ipv4_dslite.tunnel_dipv6_1,
				  entry->ipv4_dslite.tunnel_dipv6_2, entry->ipv4_dslite.tunnel_dipv6_3);
		} else if (IS_IPV6_3T_ROUTE(entry)) {
			NAT_PRINT("Information Block 2: %08X\n", entry->ipv6_3t_route.info_blk2);
			NAT_PRINT("Create IPv6 3-Tuple entry\n");
			NAT_PRINT
			    ("ING SIPv6->DIPv6: %08X:%08X:%08X:%08X-> %08X:%08X:%08X:%08X (Prot=%d)\n",
			     entry->ipv6_3t_route.ipv6_sip0, entry->ipv6_3t_route.ipv6_sip1,
			     entry->ipv6_3t_route.ipv6_sip2, entry->ipv6_3t_route.ipv6_sip3,
			     entry->ipv6_3t_route.ipv6_dip0, entry->ipv6_3t_route.ipv6_dip1,
			     entry->ipv6_3t_route.ipv6_dip2, entry->ipv6_3t_route.ipv6_dip3,
			     entry->ipv6_3t_route.prot);
		} else if (IS_IPV6_5T_ROUTE(entry)) {
			NAT_PRINT("Information Block 2: %08X\n", entry->ipv6_5t_route.info_blk2);
			NAT_PRINT("Create IPv6 5-Tuple entry\n");
			if (IS_IPV6_FLAB_EBL()) {
				NAT_PRINT
				    ("ING SIPv6->DIPv6: %08X:%08X:%08X:%08X-> %08X:%08X:%08X:%08X (Flow Label=%08X)\n",
				     entry->ipv6_5t_route.ipv6_sip0, entry->ipv6_5t_route.ipv6_sip1,
				     entry->ipv6_5t_route.ipv6_sip2, entry->ipv6_5t_route.ipv6_sip3,
				     entry->ipv6_5t_route.ipv6_dip0, entry->ipv6_5t_route.ipv6_dip1,
				     entry->ipv6_5t_route.ipv6_dip2, entry->ipv6_5t_route.ipv6_dip3,
				     ((entry->ipv6_5t_route.sport << 16) | (entry->ipv6_5t_route.
									    dport)) & 0xFFFFF);
			} else {
				NAT_PRINT
				    ("ING SIPv6->DIPv6: %08X:%08X:%08X:%08X:%d-> %08X:%08X:%08X:%08X:%d\n",
				     entry->ipv6_5t_route.ipv6_sip0, entry->ipv6_5t_route.ipv6_sip1,
				     entry->ipv6_5t_route.ipv6_sip2, entry->ipv6_5t_route.ipv6_sip3,
				     entry->ipv6_5t_route.sport, entry->ipv6_5t_route.ipv6_dip0,
				     entry->ipv6_5t_route.ipv6_dip1, entry->ipv6_5t_route.ipv6_dip2,
				     entry->ipv6_5t_route.ipv6_dip3, entry->ipv6_5t_route.dport);
			}
		} else if (IS_IPV6_6RD(entry)) {
			NAT_PRINT("Information Block 2: %08X\n", entry->ipv6_6rd.info_blk2);
			NAT_PRINT("Create IPv6 6RD entry\n");
			if (IS_IPV6_FLAB_EBL()) {
				NAT_PRINT
				    ("ING SIPv6->DIPv6: %08X:%08X:%08X:%08X-> %08X:%08X:%08X:%08X (Flow Label=%08X)\n",
				     entry->ipv6_6rd.ipv6_sip0, entry->ipv6_6rd.ipv6_sip1,
				     entry->ipv6_6rd.ipv6_sip2, entry->ipv6_6rd.ipv6_sip3,
				     entry->ipv6_6rd.ipv6_dip0, entry->ipv6_6rd.ipv6_dip1,
				     entry->ipv6_6rd.ipv6_dip2, entry->ipv6_6rd.ipv6_dip3,
				     ((entry->ipv6_5t_route.sport << 16) | (entry->ipv6_5t_route.
									    dport)) & 0xFFFFF);
			} else {
				NAT_PRINT
				    ("ING SIPv6->DIPv6: %08X:%08X:%08X:%08X:%d-> %08X:%08X:%08X:%08X:%d\n",
				     entry->ipv6_6rd.ipv6_sip0, entry->ipv6_6rd.ipv6_sip1,
				     entry->ipv6_6rd.ipv6_sip2, entry->ipv6_6rd.ipv6_sip3,
				     entry->ipv6_6rd.sport, entry->ipv6_6rd.ipv6_dip0,
				     entry->ipv6_6rd.ipv6_dip1, entry->ipv6_6rd.ipv6_dip2,
				     entry->ipv6_6rd.ipv6_dip3, entry->ipv6_6rd.dport);
			}
		}
	}
	if (IS_IPV4_HNAPT(entry) || IS_IPV4_HNAT(entry)) {
		NAT_PRINT("DMAC=%02X:%02X:%02X:%02X:%02X:%02X SMAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
			  entry->ipv4_hnapt.dmac_hi[3], entry->ipv4_hnapt.dmac_hi[2],
			  entry->ipv4_hnapt.dmac_hi[1], entry->ipv4_hnapt.dmac_hi[0],
			  entry->ipv4_hnapt.dmac_lo[1], entry->ipv4_hnapt.dmac_lo[0],
			  entry->ipv4_hnapt.smac_hi[3], entry->ipv4_hnapt.smac_hi[2],
			  entry->ipv4_hnapt.smac_hi[1], entry->ipv4_hnapt.smac_hi[0],
			  entry->ipv4_hnapt.smac_lo[1], entry->ipv4_hnapt.smac_lo[0]);
		NAT_PRINT("State = %s, ",
			  entry->bfib1.state ==
			  0 ? "Invalid" : entry->bfib1.state ==
			  1 ? "Unbind" : entry->bfib1.state ==
			  2 ? "BIND" : entry->bfib1.state ==
			  3 ? "FIN" : "Unknown");
		NAT_PRINT("Vlan_Layer = %u, ",
			  entry->bfib1.vlan_layer);
		NAT_PRINT("Eth_type = 0x%x, Vid1 = 0x%x, Vid2 = 0x%x\n",
			  entry->ipv4_hnapt.etype, entry->ipv4_hnapt.vlan1,
			  entry->ipv4_hnapt.vlan2_winfo);
		NAT_PRINT("mib = %d, multicast = %d, pppoe = %d, proto = %s\n",
			  entry->ipv4_hnapt.iblk2.mibf,
			  entry->ipv4_hnapt.iblk2.mcast,
			  entry->ipv4_hnapt.bfib1.psn,
			  entry->ipv4_hnapt.bfib1.udp == 0 ? "TCP" :
			  entry->ipv4_hnapt.bfib1.udp == 1 ? "UDP" : "Unknown");
		NAT_PRINT("=========================================\n\n");
	} else {
		if (fe_feature & HNAT_IPV6) {
			NAT_PRINT("DMAC=%02X:%02X:%02X:%02X:%02X:%02X SMAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
				  entry->ipv6_5t_route.dmac_hi[3], entry->ipv6_5t_route.dmac_hi[2],
				  entry->ipv6_5t_route.dmac_hi[1], entry->ipv6_5t_route.dmac_hi[0],
				  entry->ipv6_5t_route.dmac_lo[1], entry->ipv6_5t_route.dmac_lo[0],
				  entry->ipv6_5t_route.smac_hi[3], entry->ipv6_5t_route.smac_hi[2],
				  entry->ipv6_5t_route.smac_hi[1], entry->ipv6_5t_route.smac_hi[0],
				  entry->ipv6_5t_route.smac_lo[1], entry->ipv6_5t_route.smac_lo[0]);
			NAT_PRINT("State = %s, ", entry->bfib1.state ==
				  0 ? "Invalid" : entry->bfib1.state ==
				  1 ? "Unbind" : entry->bfib1.state ==
				  2 ? "BIND" : entry->bfib1.state ==
				  3 ? "FIN" : "Unknown");

			NAT_PRINT("Vlan_Layer = %u, ",
				  entry->bfib1.vlan_layer);
			NAT_PRINT("Eth_type = 0x%x, Vid1 = 0x%x, Vid2 = 0x%x\n",
				  entry->ipv6_5t_route.etype,
				  entry->ipv6_5t_route.vlan1,
				  entry->ipv6_5t_route.vlan2_winfo);
			NAT_PRINT("mib = %d, multicast = %d, pppoe = %d, proto = %s\n",
				  entry->ipv6_5t_route.iblk2.mibf,
				  entry->ipv6_5t_route.iblk2.mcast,
				  entry->ipv6_5t_route.bfib1.psn,
				  entry->ipv6_5t_route.bfib1.udp ==
				  0 ? "TCP" : entry->ipv6_5t_route.bfib1.udp ==
				  1 ? "UDP" : "Unknown");
			NAT_PRINT("=========================================\n\n");
		}
	}

	if (fe_feature & PACKET_SAMPLING) {
		p = (uint32_t *)ps_entry;

		NAT_PRINT("==========<PS Table Entry=%d (%p)>===============\n", index, ps_entry);
		for (i = 0; i < 4; i++)
			pr_debug("%02d: %08X\n", i, *(p + i));
	}
}

int foe_get_all_entries(struct hwnat_args *opt1)
{
	struct foe_entry *entry;
	int hash_index = 0;
	int count = 0;		/* valid entry count */

	for (hash_index = 0; hash_index < FOE_4TB_SIZ; hash_index++) {
		entry = &ppe_foe_base[hash_index];
		if (entry->bfib1.state == opt1->entry_state) {
			opt1->entries[count].hash_index = hash_index;
			opt1->entries[count].pkt_type = entry->ipv4_hnapt.bfib1.pkt_type;

			if (IS_IPV4_HNAT(entry)) {
				opt1->entries[count].ing_sipv4 = entry->ipv4_hnapt.sip;
				opt1->entries[count].ing_dipv4 = entry->ipv4_hnapt.dip;
				opt1->entries[count].eg_sipv4 = entry->ipv4_hnapt.new_sip;
				opt1->entries[count].eg_dipv4 = entry->ipv4_hnapt.new_dip;
				count++;
			} else if (IS_IPV4_HNAPT(entry)) {
				opt1->entries[count].ing_sipv4 = entry->ipv4_hnapt.sip;
				opt1->entries[count].ing_dipv4 = entry->ipv4_hnapt.dip;
				opt1->entries[count].eg_sipv4 = entry->ipv4_hnapt.new_sip;
				opt1->entries[count].eg_dipv4 = entry->ipv4_hnapt.new_dip;
				opt1->entries[count].ing_sp = entry->ipv4_hnapt.sport;
				opt1->entries[count].ing_dp = entry->ipv4_hnapt.dport;
				opt1->entries[count].eg_sp = entry->ipv4_hnapt.new_sport;
				opt1->entries[count].eg_dp = entry->ipv4_hnapt.new_dport;
				count++;
			}
			if (fe_feature & HNAT_IPV6) {
				if (IS_IPV6_1T_ROUTE(entry)) {
					opt1->entries[count].ing_dipv6_0 = entry->ipv6_1t_route.ipv6_dip3;
					opt1->entries[count].ing_dipv6_1 = entry->ipv6_1t_route.ipv6_dip2;
					opt1->entries[count].ing_dipv6_2 = entry->ipv6_1t_route.ipv6_dip1;
					opt1->entries[count].ing_dipv6_3 = entry->ipv6_1t_route.ipv6_dip0;
					count++;
				} else if (IS_IPV4_DSLITE(entry)) {
					opt1->entries[count].ing_sipv4 = entry->ipv4_dslite.sip;
					opt1->entries[count].ing_dipv4 = entry->ipv4_dslite.dip;
					opt1->entries[count].ing_sp = entry->ipv4_dslite.sport;
					opt1->entries[count].ing_dp = entry->ipv4_dslite.dport;
					opt1->entries[count].eg_sipv6_0 = entry->ipv4_dslite.tunnel_sipv6_0;
					opt1->entries[count].eg_sipv6_1 = entry->ipv4_dslite.tunnel_sipv6_1;
					opt1->entries[count].eg_sipv6_2 = entry->ipv4_dslite.tunnel_sipv6_2;
					opt1->entries[count].eg_sipv6_3 = entry->ipv4_dslite.tunnel_sipv6_3;
					opt1->entries[count].eg_dipv6_0 = entry->ipv4_dslite.tunnel_dipv6_0;
					opt1->entries[count].eg_dipv6_1 = entry->ipv4_dslite.tunnel_dipv6_1;
					opt1->entries[count].eg_dipv6_2 = entry->ipv4_dslite.tunnel_dipv6_2;
					opt1->entries[count].eg_dipv6_3 = entry->ipv4_dslite.tunnel_dipv6_3;
					count++;
				} else if (IS_IPV6_3T_ROUTE(entry)) {
					opt1->entries[count].ing_sipv6_0 = entry->ipv6_3t_route.ipv6_sip0;
					opt1->entries[count].ing_sipv6_1 = entry->ipv6_3t_route.ipv6_sip1;
					opt1->entries[count].ing_sipv6_2 = entry->ipv6_3t_route.ipv6_sip2;
					opt1->entries[count].ing_sipv6_3 = entry->ipv6_3t_route.ipv6_sip3;
					opt1->entries[count].ing_dipv6_0 = entry->ipv6_3t_route.ipv6_dip0;
					opt1->entries[count].ing_dipv6_1 = entry->ipv6_3t_route.ipv6_dip1;
					opt1->entries[count].ing_dipv6_2 = entry->ipv6_3t_route.ipv6_dip2;
					opt1->entries[count].ing_dipv6_3 = entry->ipv6_3t_route.ipv6_dip3;
					opt1->entries[count].prot = entry->ipv6_3t_route.prot;
					count++;
				} else if (IS_IPV6_5T_ROUTE(entry)) {
					opt1->entries[count].ing_sipv6_0 = entry->ipv6_5t_route.ipv6_sip0;
					opt1->entries[count].ing_sipv6_1 = entry->ipv6_5t_route.ipv6_sip1;
					opt1->entries[count].ing_sipv6_2 = entry->ipv6_5t_route.ipv6_sip2;
					opt1->entries[count].ing_sipv6_3 = entry->ipv6_5t_route.ipv6_sip3;
					opt1->entries[count].ing_sp = entry->ipv6_5t_route.sport;
					opt1->entries[count].ing_dp = entry->ipv6_5t_route.dport;

					opt1->entries[count].ing_dipv6_0 = entry->ipv6_5t_route.ipv6_dip0;
					opt1->entries[count].ing_dipv6_1 = entry->ipv6_5t_route.ipv6_dip1;
					opt1->entries[count].ing_dipv6_2 = entry->ipv6_5t_route.ipv6_dip2;
					opt1->entries[count].ing_dipv6_3 = entry->ipv6_5t_route.ipv6_dip3;
					opt1->entries[count].ipv6_flowlabel = IS_IPV6_FLAB_EBL();
					count++;
				} else if (IS_IPV6_6RD(entry)) {
					opt1->entries[count].ing_sipv6_0 = entry->ipv6_6rd.ipv6_sip0;
					opt1->entries[count].ing_sipv6_1 = entry->ipv6_6rd.ipv6_sip1;
					opt1->entries[count].ing_sipv6_2 = entry->ipv6_6rd.ipv6_sip2;
					opt1->entries[count].ing_sipv6_3 = entry->ipv6_6rd.ipv6_sip3;

					opt1->entries[count].ing_dipv6_0 = entry->ipv6_6rd.ipv6_dip0;
					opt1->entries[count].ing_dipv6_1 = entry->ipv6_6rd.ipv6_dip1;
					opt1->entries[count].ing_dipv6_2 = entry->ipv6_6rd.ipv6_dip2;
					opt1->entries[count].ing_dipv6_3 = entry->ipv6_6rd.ipv6_dip3;
					opt1->entries[count].ing_sp = entry->ipv6_6rd.sport;
					opt1->entries[count].ing_dp = entry->ipv6_6rd.dport;
					opt1->entries[count].ipv6_flowlabel = IS_IPV6_FLAB_EBL();

					opt1->entries[count].eg_sipv4 = entry->ipv6_6rd.tunnel_sipv4;
					opt1->entries[count].eg_dipv4 = entry->ipv6_6rd.tunnel_dipv4;
					count++;
				}
			}
		}
	}
	opt1->num_of_entries = count;

	if (opt1->num_of_entries > 0)
		return HWNAT_SUCCESS;
	else
		return HWNAT_ENTRY_NOT_FOUND;
}

int foe_bind_entry(struct hwnat_args *opt1)
{
	struct foe_entry *entry;

	entry = &ppe_foe_base[opt1->entry_num];

	/* restore right information block1 */
	entry->bfib1.time_stamp = reg_read(FOE_TS) & 0xFFFF;
	entry->bfib1.state = BIND;

	return HWNAT_SUCCESS;
}

int foe_un_bind_entry(struct hwnat_args *opt)
{
	struct foe_entry *entry;

	entry = &ppe_foe_base[opt->entry_num];

	entry->ipv4_hnapt.udib1.state = INVALID;
	entry->ipv4_hnapt.udib1.time_stamp = reg_read(FOE_TS) & 0xFF;

	ppe_set_cache_ebl();	/*clear HWNAT cache */

	return HWNAT_SUCCESS;
}

int _foe_drop_entry(unsigned int entry_num)
{
	struct foe_entry *entry;

	entry = &ppe_foe_base[entry_num];

	entry->ipv4_hnapt.iblk2.dp = 7;

	ppe_set_cache_ebl();	/*clear HWNAT cache */

	return HWNAT_SUCCESS;
}
EXPORT_SYMBOL(_foe_drop_entry);

int foe_drop_entry(struct hwnat_args *opt)
{
	return _foe_drop_entry(opt->entry_num);
}

int foe_del_entry_by_num(uint32_t entry_num)
{
	struct foe_entry *entry;

	entry = &ppe_foe_base[entry_num];
	memset(entry, 0, sizeof(struct foe_entry));
	ppe_set_cache_ebl();	/*clear HWNAT cache */

	return HWNAT_SUCCESS;
}

void foe_tbl_clean(void)
{
	u32 foe_tbl_size;

	foe_tbl_size = FOE_4TB_SIZ * sizeof(struct foe_entry);
	memset(ppe_foe_base, 0, foe_tbl_size);
	ppe_set_cache_ebl();	/*clear HWNAT cache */
}
EXPORT_SYMBOL(foe_tbl_clean);

void hw_nat_l2_info(struct foe_entry *entry, struct hwnat_tuple *opt)
{
	if ((opt->pkt_type) == IPV4_NAPT) {
		foe_set_mac_hi_info(entry->ipv4_hnapt.dmac_hi, opt->dmac);
		foe_set_mac_lo_info(entry->ipv4_hnapt.dmac_lo, opt->dmac);
		foe_set_mac_hi_info(entry->ipv4_hnapt.smac_hi, opt->smac);
		foe_set_mac_lo_info(entry->ipv4_hnapt.smac_lo, opt->smac);
		entry->ipv4_hnapt.vlan1 = opt->vlan1;
		/* warp hwnat not support vlan2 */
		/*mt7622 wifi hwnat not support vlan2*/
		entry->ipv4_hnapt.vlan2_winfo = opt->vlan2;

		entry->ipv4_hnapt.pppoe_id = opt->pppoe_id;
	} else if ((opt->pkt_type) == IPV6_ROUTING) {
		if (fe_feature & HNAT_IPV6) {
			foe_set_mac_hi_info(entry->ipv6_5t_route.dmac_hi, opt->dmac);
			foe_set_mac_lo_info(entry->ipv6_5t_route.dmac_lo, opt->dmac);
			foe_set_mac_hi_info(entry->ipv6_5t_route.smac_hi, opt->smac);
			foe_set_mac_lo_info(entry->ipv6_5t_route.smac_lo, opt->smac);
			entry->ipv6_5t_route.vlan1 = opt->vlan1;
			/*mt7622 wifi hwnat not support vlan2*/
			entry->ipv6_5t_route.vlan2_winfo = opt->vlan2;
			entry->ipv6_5t_route.pppoe_id = opt->pppoe_id;
		}
	}
}

void hw_nat_l3_info(struct foe_entry *entry, struct hwnat_tuple *opt)
{
	if ((opt->pkt_type) == IPV4_NAPT) {
		entry->ipv4_hnapt.sip = opt->ing_sipv4;
		entry->ipv4_hnapt.dip = opt->ing_dipv4;
		entry->ipv4_hnapt.new_sip = opt->eg_sipv4;
		entry->ipv4_hnapt.new_dip = opt->eg_dipv4;
	} else if ((opt->pkt_type) == IPV6_ROUTING) {
		if (fe_feature & HNAT_IPV6) {
			entry->ipv6_5t_route.ipv6_sip0 = opt->ing_sipv6_0;
			entry->ipv6_5t_route.ipv6_sip1 = opt->ing_sipv6_1;
			entry->ipv6_5t_route.ipv6_sip2 = opt->ing_sipv6_2;
			entry->ipv6_5t_route.ipv6_sip3 = opt->ing_sipv6_3;

			entry->ipv6_5t_route.ipv6_dip0 = opt->ing_dipv6_0;
			entry->ipv6_5t_route.ipv6_dip1 = opt->ing_dipv6_1;
			entry->ipv6_5t_route.ipv6_dip2 = opt->ing_dipv6_2;
			entry->ipv6_5t_route.ipv6_dip3 = opt->ing_dipv6_3;
		}

/*		pr_info("opt->ing_sipv6_0 = %x\n", opt->ing_sipv6_0);*/
/*		pr_info("opt->ing_sipv6_1 = %x\n", opt->ing_sipv6_1);*/
/*		pr_info("opt->ing_sipv6_2 = %x\n", opt->ing_sipv6_2);*/
/*		pr_info("opt->ing_sipv6_3 = %x\n", opt->ing_sipv6_3);*/
/*		pr_info("opt->ing_dipv6_0 = %x\n", opt->ing_dipv6_0);*/
/*		pr_info("opt->ing_dipv6_1 = %x\n", opt->ing_dipv6_1);*/
/*		pr_info("opt->ing_dipv6_2 = %x\n", opt->ing_dipv6_2);*/
/*		pr_info("opt->ing_dipv6_3 = %x\n", opt->ing_dipv6_3);*/

/*		pr_info("entry->ipv6_5t_route.ipv6_sip0 = %x\n", entry->ipv6_5t_route.ipv6_sip0);*/
/*		pr_info("entry->ipv6_5t_route.ipv6_sip1 = %x\n", entry->ipv6_5t_route.ipv6_sip1);*/
/*		pr_info("entry->ipv6_5t_route.ipv6_sip2 = %x\n", entry->ipv6_5t_route.ipv6_sip2);*/
/*		pr_info("entry->ipv6_5t_route.ipv6_sip3 = %x\n", entry->ipv6_5t_route.ipv6_sip3);*/
/*		pr_info("entry->ipv6_5t_route.ipv6_dip0 = %x\n", entry->ipv6_5t_route.ipv6_dip0);*/
/*		pr_info("entry->ipv6_5t_route.ipv6_dip1 = %x\n", entry->ipv6_5t_route.ipv6_dip1);*/
/*		pr_info("entry->ipv6_5t_route.ipv6_dip2 = %x\n", entry->ipv6_5t_route.ipv6_dip2);*/
/*		pr_info("entry->ipv6_5t_route.ipv6_dip3 = %x\n", entry->ipv6_5t_route.ipv6_dip3);*/
	}
}

void hw_nat_l4_info(struct foe_entry *entry, struct hwnat_tuple *opt)
{
	if ((opt->pkt_type) == IPV4_NAPT) {
		entry->ipv4_hnapt.dport = opt->ing_dp;
		entry->ipv4_hnapt.sport = opt->ing_sp;
		entry->ipv4_hnapt.new_dport = opt->eg_dp;
		entry->ipv4_hnapt.new_sport = opt->eg_sp;
	} else if ((opt->pkt_type) == IPV6_ROUTING) {
		if (fe_feature & HNAT_IPV6) {
			entry->ipv6_5t_route.dport = opt->ing_dp;
			entry->ipv6_5t_route.sport = opt->ing_sp;
		}
	}
}

void hw_nat_ib1_info(struct foe_entry *entry, struct hwnat_tuple *opt)
{
	if ((opt->pkt_type) == IPV4_NAPT) {
		entry->ipv4_hnapt.bfib1.pkt_type = IPV4_NAPT;
		entry->ipv4_hnapt.bfib1.sta = 1;
		entry->ipv4_hnapt.bfib1.udp = opt->is_udp; /* tcp/udp */
		entry->ipv4_hnapt.bfib1.state = BIND;
		entry->ipv4_hnapt.bfib1.ka = 1; /* keepalive */
		entry->ipv4_hnapt.bfib1.ttl = 0; /* TTL-1 */
		entry->ipv4_hnapt.bfib1.psn = opt->pppoe_act; /* insert / remove */
		entry->ipv4_hnapt.bfib1.vlan_layer = opt->vlan_layer;
		entry->ipv4_hnapt.bfib1.time_stamp = reg_read(FOE_TS) & 0xFFFF;
	} else if ((opt->pkt_type) == IPV6_ROUTING) {
		if (fe_feature & HNAT_IPV6) {
			entry->ipv6_5t_route.bfib1.pkt_type = IPV6_ROUTING;
			entry->ipv6_5t_route.bfib1.sta = 1;
			entry->ipv6_5t_route.bfib1.udp = opt->is_udp; /* tcp/udp */
			entry->ipv6_5t_route.bfib1.state = BIND;
			entry->ipv6_5t_route.bfib1.ka = 1; /* keepalive */
			entry->ipv6_5t_route.bfib1.ttl = 0; /* TTL-1 */
			entry->ipv6_5t_route.bfib1.psn = opt->pppoe_act; /* insert / remove */
			entry->ipv6_5t_route.bfib1.vlan_layer = opt->vlan_layer;
			entry->ipv6_5t_route.bfib1.time_stamp = reg_read(FOE_TS) & 0xFFFF;
		}
	}
}

void hw_nat_ib2_info(struct foe_entry *entry, struct hwnat_tuple *opt)
{
	if ((opt->pkt_type) == IPV4_NAPT) {
		entry->ipv4_hnapt.iblk2.dp = opt->dst_port; /* 0:cpu, 1:GE1 */
		entry->ipv4_hnapt.iblk2.dscp = opt->dscp;
		entry->ipv4_hnapt.iblk2.acnt = opt->dst_port;
	} else if ((opt->pkt_type) == IPV6_ROUTING) {
		if (fe_feature & HNAT_IPV6) {
			entry->ipv6_5t_route.iblk2.dp = opt->dst_port; /* 0:cpu, 1:GE1 */
			entry->ipv6_5t_route.iblk2.dscp = opt->dscp;
			entry->ipv6_5t_route.iblk2.acnt = opt->dst_port;
		}
	}
}

void hw_nat_semi_bind(struct foe_entry *entry, struct hwnat_tuple *opt)
{
	u32 current_time;

	if ((opt->pkt_type) == IPV4_NAPT) {
		/* Set Current time to time_stamp field in information block 1 */
		current_time = reg_read(FOE_TS) & 0xFFFF;
		entry->bfib1.time_stamp = (uint16_t)current_time;
		/* Ipv4: TTL / Ipv6: Hot Limit filed */
		entry->ipv4_hnapt.bfib1.ttl = DFL_FOE_TTL_REGEN;
		/* enable cache by default */
		entry->ipv4_hnapt.bfib1.cah = 1;
		/* Change Foe Entry State to Binding State */
		entry->bfib1.state = BIND;
	} else if ((opt->pkt_type) == IPV6_ROUTING) {
		if (fe_feature & HNAT_IPV6) {
			/* Set Current time to time_stamp field in information block 1 */
			current_time = reg_read(FOE_TS) & 0xFFFF;
			entry->bfib1.time_stamp = (uint16_t)current_time;
			/* Ipv4: TTL / Ipv6: Hot Limit filed */
			entry->ipv4_hnapt.bfib1.ttl = DFL_FOE_TTL_REGEN;
			/* enable cache by default */
			entry->ipv4_hnapt.bfib1.cah = 1;
			/* Change Foe Entry State to Binding State */
			entry->bfib1.state = BIND;
		}
	}
}

int set_done_bit_zero(struct foe_entry *foe_entry)
{
	if (IS_IPV4_HNAT(foe_entry) || IS_IPV4_HNAPT(foe_entry))
		foe_entry->ipv4_hnapt.resv1 = 0;

	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV4_DSLITE(foe_entry)) {
			foe_entry->ipv4_dslite.resv1 = 0;
		} else if (IS_IPV6_3T_ROUTE(foe_entry)) {
			foe_entry->ipv6_3t_route.resv1 = 0;
		} else if (IS_IPV6_5T_ROUTE(foe_entry)) {
			foe_entry->ipv6_5t_route.resv1 = 0;
		} else if (IS_IPV6_6RD(foe_entry)) {
			foe_entry->ipv6_6rd.resv1 = 0;
		} else {
			pr_info("%s:get packet format something wrong\n", __func__);
			return -1;
		}
	}
	return 0;
}

int get_entry_done_bit(struct foe_entry *foe_entry)
{
	int done_bit;

	if (IS_IPV4_HNAT(foe_entry) || IS_IPV4_HNAPT(foe_entry))
		done_bit = foe_entry->ipv4_hnapt.resv1;

	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV4_DSLITE(foe_entry)) {
			done_bit = foe_entry->ipv4_dslite.resv1;
		} else if (IS_IPV6_3T_ROUTE(foe_entry)) {
			done_bit = foe_entry->ipv6_3t_route.resv1;
		} else if (IS_IPV6_5T_ROUTE(foe_entry)) {
			done_bit = foe_entry->ipv6_5t_route.resv1;
		} else if (IS_IPV6_6RD(foe_entry)) {
			done_bit = foe_entry->ipv6_6rd.resv1;
		} else {
			pr_info("%s:get packet format something wrong\n", __func__);
			return -1;
		}
	}

	return done_bit;
}

int foe_add_entry(struct hwnat_tuple *opt)
{
	struct foe_pri_key key;
	struct foe_entry *entry = NULL;
	s32 hash_index;
	int done_bit;

	if ((opt->pkt_type) == IPV4_NAPT) {
		key.ipv4_hnapt.sip = opt->ing_sipv4;
		key.ipv4_hnapt.dip = opt->ing_dipv4;
		key.ipv4_hnapt.sport = opt->ing_sp;
		key.ipv4_hnapt.dport = opt->ing_dp;
		key.ipv4_hnapt.is_udp = opt->is_udp;
	} else if ((opt->pkt_type) == IPV6_ROUTING) {
		key.ipv6_routing.sip0 = opt->ing_sipv6_0;
		key.ipv6_routing.sip1 = opt->ing_sipv6_1;
		key.ipv6_routing.sip2 = opt->ing_sipv6_2;
		key.ipv6_routing.sip3 = opt->ing_sipv6_3;
		key.ipv6_routing.dip0 = opt->ing_dipv6_0;
		key.ipv6_routing.dip1 = opt->ing_dipv6_1;
		key.ipv6_routing.dip2 = opt->ing_dipv6_2;
		key.ipv6_routing.dip3 = opt->ing_dipv6_3;
		key.ipv6_routing.sport = opt->ing_sp;
		key.ipv6_routing.dport = opt->ing_dp;
		key.ipv6_routing.is_udp = opt->is_udp;
	}

	key.pkt_type = opt->pkt_type;

	if (fe_feature & MANUAL_MODE)
		hash_index = get_ppe_entry_idx(&key, entry, 0);
	else
		hash_index = get_ppe_entry_idx(&key, entry, 1);

	if (hash_index != -1) {
		opt->hash_index = hash_index;
		entry =  &ppe_foe_base[hash_index];
		if (fe_feature & MANUAL_MODE) {
			hw_nat_l2_info(entry, opt);
			hw_nat_l3_info(entry, opt);
			hw_nat_l4_info(entry, opt);
			hw_nat_ib1_info(entry, opt);
			hw_nat_ib2_info(entry, opt);
		}
		if (fe_feature & SEMI_AUTO_MODE) {
			done_bit = get_entry_done_bit(entry);
			if (done_bit == 1)
				pr_info("mtk_entry_add number =%d\n", hash_index);
			else if (done_bit == 0)
				pr_info("ppe table not ready\n");
			else
				pr_info("%s: done_bit something wrong\n", __func__);

			if (done_bit != 1)
				return HWNAT_FAIL;
			hw_nat_semi_bind(entry, opt);
		}
		foe_dump_entry(hash_index);
		return HWNAT_SUCCESS;
	}

	return HWNAT_FAIL;
}

int foe_del_entry(struct hwnat_tuple *opt)
{
	struct foe_pri_key key;
	s32 hash_index;
	struct foe_entry *entry = NULL;
	s32 rply_idx;
	int done_bit;

	if ((opt->pkt_type) == IPV4_NAPT) {
		key.ipv4_hnapt.sip = opt->ing_sipv4;
		key.ipv4_hnapt.dip = opt->ing_dipv4;
		key.ipv4_hnapt.sport = opt->ing_sp;
		key.ipv4_hnapt.dport = opt->ing_dp;
		/* key.ipv4_hnapt.is_udp=opt->is_udp; */
	} else if ((opt->pkt_type) == IPV6_ROUTING) {
		key.ipv6_routing.sip0 = opt->ing_sipv6_0;
		key.ipv6_routing.sip1 = opt->ing_sipv6_1;
		key.ipv6_routing.sip2 = opt->ing_sipv6_2;
		key.ipv6_routing.sip3 = opt->ing_sipv6_3;
		key.ipv6_routing.dip0 = opt->ing_dipv6_0;
		key.ipv6_routing.dip1 = opt->ing_dipv6_1;
		key.ipv6_routing.dip2 = opt->ing_dipv6_2;
		key.ipv6_routing.dip3 = opt->ing_dipv6_3;
		key.ipv6_routing.sport = opt->ing_sp;
		key.ipv6_routing.dport = opt->ing_dp;
		/* key.ipv6_routing.is_udp=opt->is_udp; */
	}

	key.pkt_type = opt->pkt_type;

	/* find bind entry */
	/* hash_index = FoeHashFun(&key,BIND); */
	hash_index = get_ppe_entry_idx(&key, entry, 1);
	if (hash_index != -1) {
		opt->hash_index = hash_index;
		rply_idx = reply_entry_idx(opt, hash_index);
		if (fe_feature & SEMI_AUTO_MODE) {
			entry =  &ppe_foe_base[hash_index];
			done_bit = get_entry_done_bit(entry);
			if (done_bit == 1) {
				set_done_bit_zero(entry);
			} else if (done_bit == 0) {
				pr_info("%s : ppe table not ready\n", __func__);
			} else {
				pr_info("%s: done_bit something wrong\n", __func__);
				set_done_bit_zero(entry);
			}
			if (done_bit != 1)
				return HWNAT_FAIL;
		}
		foe_del_entry_by_num(hash_index);
		pr_info("Clear Entry index = %d\n", hash_index);
		if (rply_idx != -1) {
		pr_info("Clear Entry index = %d\n", rply_idx);
			foe_del_entry_by_num(rply_idx);
		}

		return HWNAT_SUCCESS;
	}
	pr_info("HWNAT ENTRY NOT FOUND\n");
	return HWNAT_ENTRY_NOT_FOUND;
}
EXPORT_SYMBOL(foe_del_entry);

int get_five_tule(struct sk_buff *skb)
{
	struct ethhdr *eth = NULL;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct tcphdr *th = NULL;
	struct udphdr *uh = NULL;
	u8 ipv6_head_len = 0;

	memset(&ppe_parse_rx_result, 0, sizeof(ppe_parse_rx_result));
	eth = (struct ethhdr *)skb->data;
	ppe_parse_rx_result.eth_type = eth->h_proto;
	/* set layer4 start addr */
	if ((ppe_parse_rx_result.eth_type == htons(ETH_P_IP)) ||
	    (ppe_parse_rx_result.eth_type == htons(ETH_P_PPP_SES) &&
	    (ppe_parse_rx_result.ppp_tag == htons(PPP_IP)))) {
		iph = (struct iphdr *)(skb->data + ETH_HLEN);
		memcpy(&ppe_parse_rx_result.iph, iph, sizeof(struct iphdr));
		if (iph->protocol == IPPROTO_TCP) {
			skb_set_transport_header(skb, ETH_HLEN + (iph->ihl * 4));
			th = (struct tcphdr *)skb_transport_header(skb);
			memcpy(&ppe_parse_rx_result.th, th, sizeof(struct tcphdr));
			ppe_parse_rx_result.pkt_type = IPV4_HNAPT;
			if (iph->frag_off & htons(IP_MF | IP_OFFSET)) {
				if (debug_level >= 2)
					DD;
				return 1;
			}
		} else if (iph->protocol == IPPROTO_UDP) {
			skb_set_transport_header(skb, ETH_HLEN + (iph->ihl * 4));
			uh = (struct udphdr *)skb_transport_header(skb);
			memcpy(&ppe_parse_rx_result.uh, uh, sizeof(struct udphdr));
			ppe_parse_rx_result.pkt_type = IPV4_HNAPT;
			if (iph->frag_off & htons(IP_MF | IP_OFFSET)) {
				if (USE_3T_UDP_FRAG == 0)
					return 1;
			}
		} else if (iph->protocol == IPPROTO_GRE) {
			if (debug_level >= 2)
				/* do nothing */
				return 1;
		}
		if (fe_feature & HNAT_IPV6) {
			if (iph->protocol == IPPROTO_IPV6) {
				ip6h = (struct ipv6hdr *)((uint8_t *)iph + iph->ihl * 4);
				memcpy(&ppe_parse_rx_result.ip6h, ip6h, sizeof(struct ipv6hdr));
				if (ip6h->nexthdr == NEXTHDR_TCP) {
					skb_set_transport_header(skb, ETH_HLEN + (sizeof(struct ipv6hdr)));
					th = (struct tcphdr *)skb_transport_header(skb);
					memcpy(&ppe_parse_rx_result.th.source, &th->source, sizeof(th->source));
					memcpy(&ppe_parse_rx_result.th.dest, &th->dest, sizeof(th->dest));
				} else if (ip6h->nexthdr == NEXTHDR_UDP) {
					skb_set_transport_header(skb, ETH_HLEN + (sizeof(struct ipv6hdr)));
					uh = (struct udphdr *)skb_transport_header(skb);
					memcpy(&ppe_parse_rx_result.uh.source, &uh->source, sizeof(uh->source));
					memcpy(&ppe_parse_rx_result.uh.dest, &uh->dest, sizeof(uh->dest));
				}
					ppe_parse_rx_result.pkt_type = IPV6_6RD;
				if (hnat_chip_name & MT7621_HWNAT)
					return 1;
		/* identification field in outer ipv4 header is zero*/
		/*after erntering binding state.*/
		/* some 6rd relay router will drop the packet */
			}
		}
		if ((iph->protocol != IPPROTO_TCP) && (iph->protocol != IPPROTO_UDP) &&
		    (iph->protocol != IPPROTO_GRE) && (iph->protocol != IPPROTO_IPV6))
			return 1;
				/* Packet format is not supported */

	} else if (ppe_parse_rx_result.eth_type == htons(ETH_P_IPV6) ||
		   (ppe_parse_rx_result.eth_type == htons(ETH_P_PPP_SES) &&
		    ppe_parse_rx_result.ppp_tag == htons(PPP_IPV6))) {
		ip6h = (struct ipv6hdr *)skb_network_header(skb);
		memcpy(&ppe_parse_rx_result.ip6h, ip6h, sizeof(struct ipv6hdr));
		if (ip6h->nexthdr == NEXTHDR_TCP) {
			skb_set_transport_header(skb, ETH_HLEN + (sizeof(struct ipv6hdr)));
			th = (struct tcphdr *)skb_transport_header(skb);
			memcpy(&ppe_parse_rx_result.th, th, sizeof(struct tcphdr));
			ppe_parse_rx_result.pkt_type = IPV6_5T_ROUTE;
		} else if (ip6h->nexthdr == NEXTHDR_UDP) {
			skb_set_transport_header(skb, ETH_HLEN + (sizeof(struct ipv6hdr)));
			uh = (struct udphdr *)skb_transport_header(skb);
			memcpy(&ppe_parse_rx_result.uh, uh, sizeof(struct udphdr));
			ppe_parse_rx_result.pkt_type = IPV6_5T_ROUTE;
		} else if (ip6h->nexthdr == NEXTHDR_IPIP) {
			ipv6_head_len = sizeof(struct iphdr);
			memcpy(&ppe_parse_rx_result.iph, ip6h + ipv6_head_len,
			       sizeof(struct iphdr));
			ppe_parse_rx_result.pkt_type = IPV4_DSLITE;
		} else {
			ppe_parse_rx_result.pkt_type = IPV6_3T_ROUTE;
		}

	} else {
				if (debug_level >= 2)
					DD;
		return 1;
	}
	return 0;
}

int decide_qid(u16 hash_index, struct sk_buff *skb)
{
	struct foe_entry *entry;
	u32 saddr;
	u32 daddr;

	u32 ppe_saddr;
	u32 ppe_daddr;
	u32 ppe_sport;
	u32 ppe_dport;

	u32 sport;
	u32 dport;

	u32 ipv6_sip_127_96;
	u32 ipv6_sip_95_64;
	u32 ipv6_sip_63_32;
	u32 ipv6_sip_31_0;

	u32 ipv6_dip_127_96;
	u32 ipv6_dip_95_64;
	u32 ipv6_dip_63_32;
	u32 ipv6_dip_31_0;

	u32 ppe_saddr_127_96;
	u32 ppe_saddr_95_64;
	u32 ppe_saddr_63_32;
	u32 ppe_saddr_31_0;

	u32 ppe_daddr_127_96;
	u32 ppe_daddr_95_64;
	u32 ppe_daddr_63_32;
	u32 ppe_daddr_31_0;

	u32 ppe_sportv6;
	u32 ppe_dportv6;

	entry = &ppe_foe_base[hash_index];
	if (IS_IPV4_HNAPT(entry)) {
		saddr = ntohl(ppe_parse_rx_result.iph.saddr);
		daddr = ntohl(ppe_parse_rx_result.iph.daddr);
		if (ppe_parse_rx_result.iph.protocol == IPPROTO_TCP) {
			sport = ntohs(ppe_parse_rx_result.th.source);
			dport = ntohs(ppe_parse_rx_result.th.dest);
		} else if (ppe_parse_rx_result.iph.protocol == IPPROTO_UDP) {
			sport = ntohs(ppe_parse_rx_result.uh.source);
			dport = ntohs(ppe_parse_rx_result.uh.dest);
		}
		ppe_saddr = entry->ipv4_hnapt.sip;
		ppe_daddr = entry->ipv4_hnapt.dip;
		ppe_sport = entry->ipv4_hnapt.sport;
		ppe_dport = entry->ipv4_hnapt.dport;
		if (debug_level >= 2) {
			pr_info("ppe_saddr = %x, ppe_daddr=%x, ppe_sport=%d, ppe_dport=%d, saddr=%x, daddr=%x, sport= %d, dport=%d\n",
				ppe_saddr, ppe_daddr, ppe_sport, ppe_dport, saddr, daddr, sport, dport);
		}
		if ((saddr == ppe_saddr) && (daddr == ppe_daddr) &&
		    (sport == ppe_sport) && (dport == ppe_dport) &&
		    (entry->bfib1.state == BIND)) {
			if (entry->ipv4_hnapt.iblk2.dp == 2) {
				skb->dev = dst_port[DP_GMAC2];
				if (debug_level >= 2)
					pr_info("qid = %d\n", entry->ipv4_hnapt.iblk2.qid);
				skb->mark = entry->ipv4_hnapt.iblk2.qid;
			} else{
				skb->dev = dst_port[DP_GMAC1];
				if (debug_level >= 2)
					pr_info("qid = %d\n", entry->ipv4_hnapt.iblk2.qid);
				skb->mark = entry->ipv4_hnapt.iblk2.qid;
			}
			return 0;
		} else {
			return -1;
		}
	}
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV6_5T_ROUTE(entry)) {
			ipv6_sip_127_96 = ntohl(ppe_parse_rx_result.ip6h.saddr.s6_addr32[0]);
			ipv6_sip_95_64 = ntohl(ppe_parse_rx_result.ip6h.saddr.s6_addr32[1]);
			ipv6_sip_63_32 = ntohl(ppe_parse_rx_result.ip6h.saddr.s6_addr32[2]);
			ipv6_sip_31_0 = ntohl(ppe_parse_rx_result.ip6h.saddr.s6_addr32[3]);

			ipv6_dip_127_96 = ntohl(ppe_parse_rx_result.ip6h.daddr.s6_addr32[0]);
			ipv6_dip_95_64 = ntohl(ppe_parse_rx_result.ip6h.daddr.s6_addr32[1]);
			ipv6_dip_63_32 = ntohl(ppe_parse_rx_result.ip6h.daddr.s6_addr32[2]);
			ipv6_dip_31_0 = ntohl(ppe_parse_rx_result.ip6h.daddr.s6_addr32[3]);

			ppe_saddr_127_96 = entry->ipv6_5t_route.ipv6_sip0;
			ppe_saddr_95_64 = entry->ipv6_5t_route.ipv6_sip1;
			ppe_saddr_63_32 = entry->ipv6_5t_route.ipv6_sip2;
			ppe_saddr_31_0 = entry->ipv6_5t_route.ipv6_sip3;

			ppe_daddr_127_96 = entry->ipv6_5t_route.ipv6_dip0;
			ppe_daddr_95_64 = entry->ipv6_5t_route.ipv6_dip1;
			ppe_daddr_63_32 = entry->ipv6_5t_route.ipv6_dip2;
			ppe_daddr_31_0 = entry->ipv6_5t_route.ipv6_dip3;

			ppe_sportv6 = entry->ipv6_5t_route.sport;
			ppe_dportv6 = entry->ipv6_5t_route.dport;
			if (ppe_parse_rx_result.iph.protocol == IPPROTO_TCP) {
				sport = ntohs(ppe_parse_rx_result.th.source);
				dport = ntohs(ppe_parse_rx_result.th.dest);
			} else if (ppe_parse_rx_result.iph.protocol == IPPROTO_UDP) {
				sport = ntohs(ppe_parse_rx_result.uh.source);
				dport = ntohs(ppe_parse_rx_result.uh.dest);
			}
			if ((ipv6_sip_127_96 == ppe_saddr_127_96) && (ipv6_sip_95_64 == ppe_saddr_95_64) &&
			    (ipv6_sip_63_32 == ppe_saddr_63_32) && (ipv6_sip_31_0 == ppe_saddr_31_0) &&
			    (ipv6_dip_127_96 == ppe_daddr_127_96) && (ipv6_dip_95_64 == ppe_daddr_95_64) &&
			    (ipv6_dip_63_32 == ppe_daddr_63_32) && (ipv6_dip_31_0 == ppe_daddr_31_0) &&
			    (sport == ppe_sportv6) && (dport == ppe_dportv6) &&
			    (entry->bfib1.state == BIND)) {
				if (entry->ipv6_5t_route.iblk2.dp == 2) {
					skb->dev = dst_port[DP_GMAC2];
						/* if (entry->ipv6_3t_route.iblk2.qid >= 11) */
					skb->mark = (entry->ipv6_3t_route.iblk2.qid);
				} else{
					skb->dev = dst_port[DP_GMAC1];
					skb->mark = (entry->ipv6_3t_route.iblk2.qid);
				}
			} else {
				return -1;
			}
		}
	}
	return 0;
}

void set_qid(struct sk_buff *skb)
{
	struct foe_pri_key key;
	s32 hash_index;
	struct foe_entry *entry = NULL;

	get_five_tule(skb);
	if (ppe_parse_rx_result.pkt_type == IPV4_HNAPT) {
		key.ipv4_hnapt.sip = ntohl(ppe_parse_rx_result.iph.saddr);
		key.ipv4_hnapt.dip = ntohl(ppe_parse_rx_result.iph.daddr);

		if (ppe_parse_rx_result.iph.protocol == IPPROTO_TCP) {
			key.ipv4_hnapt.sport = ntohs(ppe_parse_rx_result.th.source);
			key.ipv4_hnapt.dport = ntohs(ppe_parse_rx_result.th.dest);
		} else if (ppe_parse_rx_result.iph.protocol == IPPROTO_UDP) {
			key.ipv4_hnapt.sport = ntohs(ppe_parse_rx_result.uh.source);
			key.ipv4_hnapt.dport = ntohs(ppe_parse_rx_result.uh.dest);
		}
		/* key.ipv4_hnapt.is_udp=opt->is_udp; */
	} else if (ppe_parse_rx_result.pkt_type == IPV6_5T_ROUTE) {
		key.ipv6_routing.sip0 = ntohl(ppe_parse_rx_result.ip6h.saddr.s6_addr32[0]);
		key.ipv6_routing.sip1 = ntohl(ppe_parse_rx_result.ip6h.saddr.s6_addr32[1]);
		key.ipv6_routing.sip2 = ntohl(ppe_parse_rx_result.ip6h.saddr.s6_addr32[2]);
		key.ipv6_routing.sip3 = ntohl(ppe_parse_rx_result.ip6h.saddr.s6_addr32[3]);
		key.ipv6_routing.dip0 = ntohl(ppe_parse_rx_result.ip6h.daddr.s6_addr32[0]);
		key.ipv6_routing.dip1 = ntohl(ppe_parse_rx_result.ip6h.daddr.s6_addr32[1]);
		key.ipv6_routing.dip2 = ntohl(ppe_parse_rx_result.ip6h.daddr.s6_addr32[2]);
		key.ipv6_routing.dip3 = ntohl(ppe_parse_rx_result.ip6h.daddr.s6_addr32[3]);
		if (ppe_parse_rx_result.ip6h.nexthdr == IPPROTO_TCP) {
			key.ipv6_routing.sport = ntohs(ppe_parse_rx_result.th.source);
			key.ipv6_routing.dport = ntohs(ppe_parse_rx_result.th.dest);
		} else if (ppe_parse_rx_result.ip6h.nexthdr == IPPROTO_UDP) {
			key.ipv6_routing.sport = ntohs(ppe_parse_rx_result.uh.source);
			key.ipv6_routing.dport = ntohs(ppe_parse_rx_result.uh.dest);
		}
	}

	key.pkt_type = ppe_parse_rx_result.pkt_type;

	/* find bind entry */
	/* hash_index = FoeHashFun(&key,BIND); */
	hash_index = get_ppe_entry_idx(&key, entry, 1);
	if (hash_index != -1)
		decide_qid(hash_index, skb);
	if (debug_level >= 6)
		pr_info("hash_index = %d\n", hash_index);
}
