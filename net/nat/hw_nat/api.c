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
#include <linux/skbuff.h>
#include <net/ra_nat.h>

#include "foe_fdb.h"
#include "frame_engine.h"
#include "util.h"
#include "hwnat_ioctl.h"
#include "api.h"
#include "hwnat_define.h"

#if defined(CONFIG_RA_HW_NAT_IPV6)
int hash_ipv6(struct foe_pri_key *key, struct foe_entry *entry, int del)
{
	u32 t_hvt_31, t_hvt_63, t_hvt_95, t_hvt_sd;
	u32 t_hvt_sd_23, t_hvt_sd_31_24, t_hash_32, t_hashs_16, t_ha16k, hash_index;
	u32 ppe_saddr_127_96, ppe_saddr_95_64, ppe_saddr_63_32, ppe_saddr_31_0;
	u32 ppe_daddr_127_96, ppe_daddr_95_64, ppe_daddr_63_32, ppe_daddr_31_0;
	u32 ipv6_sip_127_96, ipv6_sip_95_64, ipv6_sip_63_32, ipv6_sip_31_0;
	u32 ipv6_dip_127_96, ipv6_dip_95_64, ipv6_dip_63_32, ipv6_dip_31_0;
	u32 sport, dport, ppe_sportv6, ppe_dportv6;

	ipv6_sip_127_96 = key->ipv6_routing.sip0;
	ipv6_sip_95_64 = key->ipv6_routing.sip1;
	ipv6_sip_63_32 = key->ipv6_routing.sip2;
	ipv6_sip_31_0 = key->ipv6_routing.sip3;
	ipv6_dip_127_96 = key->ipv6_routing.dip0;
	ipv6_dip_95_64 = key->ipv6_routing.dip1;
	ipv6_dip_63_32 = key->ipv6_routing.dip2;
	ipv6_dip_31_0 = key->ipv6_routing.dip3;
	sport = key->ipv6_routing.sport;
	dport = key->ipv6_routing.dport;

	t_hvt_31 = ipv6_sip_31_0 ^ ipv6_dip_31_0 ^ (sport << 16 | dport);
	t_hvt_63 = ipv6_sip_63_32 ^ ipv6_dip_63_32 ^ ipv6_dip_127_96;
	t_hvt_95 = ipv6_sip_95_64 ^ ipv6_dip_95_64 ^ ipv6_sip_127_96;
	if (DFL_FOE_HASH_MODE == 1)	/* hash mode 1 */
		t_hvt_sd = (t_hvt_31 & t_hvt_63) | ((~t_hvt_31) & t_hvt_95);
	else                            /* hash mode 2 */
		t_hvt_sd = t_hvt_63 ^ (t_hvt_31 & (~t_hvt_95));

	t_hvt_sd_23 = t_hvt_sd & 0xffffff;
	t_hvt_sd_31_24 = t_hvt_sd & 0xff000000;
	t_hash_32 = t_hvt_31 ^ t_hvt_63 ^ t_hvt_95 ^ ((t_hvt_sd_23 << 8) | (t_hvt_sd_31_24 >> 24));
	t_hashs_16 = ((t_hash_32 & 0xffff0000) >> 16) ^ (t_hash_32 & 0xfffff);

	if (FOE_4TB_SIZ == 16384)
		t_ha16k = t_hashs_16 & 0x1fff;  /* FOE_16k */
	else if (FOE_4TB_SIZ == 8192)
		t_ha16k = t_hashs_16 & 0xfff;  /* FOE_8k */
	else if (FOE_4TB_SIZ == 4096)
		t_ha16k = t_hashs_16 & 0x7ff;  /* FOE_4k */
	else if (FOE_4TB_SIZ == 2048)
		t_ha16k = t_hashs_16 & 0x3ff;  /* FOE_2k */
	else
		t_ha16k = t_hashs_16 & 0x1ff;  /* FOE_1k */
	hash_index = (u32)t_ha16k * 2;

	entry = &ppe_foe_base[hash_index];
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
	if (del != 1) {
		if (entry->ipv6_5t_route.bfib1.state == BIND) {
			pr_info("IPV6 Hash collision, hash index +1\n");
			hash_index = hash_index + 1;
			entry = &ppe_foe_base[hash_index];
		}
		if (entry->ipv6_5t_route.bfib1.state == BIND) {
			pr_info("IPV6 Hash collision can not bind\n");
			return -1;
		}
	} else if (del == 1) {
		if ((ipv6_sip_127_96 == ppe_saddr_127_96) && (ipv6_sip_95_64 == ppe_saddr_95_64) &&
		    (ipv6_sip_63_32 == ppe_saddr_63_32) && (ipv6_sip_31_0 == ppe_saddr_31_0) &&
		    (ipv6_dip_127_96 == ppe_daddr_127_96) && (ipv6_dip_95_64 == ppe_daddr_95_64) &&
		    (ipv6_dip_63_32 == ppe_daddr_63_32) && (ipv6_dip_31_0 == ppe_daddr_31_0) &&
		    (sport == ppe_sportv6) && (dport == ppe_dportv6)) {
		} else {
			hash_index = hash_index + 1;
			entry = &ppe_foe_base[hash_index];
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
			if ((ipv6_sip_127_96 == ppe_saddr_127_96) && (ipv6_sip_95_64 == ppe_saddr_95_64) &&
			    (ipv6_sip_63_32 == ppe_saddr_63_32) && (ipv6_sip_31_0 == ppe_saddr_31_0) &&
			    (ipv6_dip_127_96 == ppe_daddr_127_96) && (ipv6_dip_95_64 == ppe_daddr_95_64) &&
			    (ipv6_dip_63_32 == ppe_daddr_63_32) && (ipv6_dip_31_0 == ppe_daddr_31_0) &&
			    (sport == ppe_sportv6) && (dport == ppe_dportv6)) {
			} else {
				if (fe_feature & SEMI_AUTO_MODE)
					pr_info("Ipv6 Entry delete : Entry Not found\n");
				else if (fe_feature & MANUAL_MODE)
					pr_info("Ipv6 hash collision hwnat can not found\n");
				return -1;
			}
		}
	}
	return hash_index;
}

int hash_mib_ipv6(struct foe_pri_key *key, struct foe_entry *entry)
{
	u32 t_hvt_31, t_hvt_63, t_hvt_95, t_hvt_sd;
	u32 t_hvt_sd_23, t_hvt_sd_31_24, t_hash_32, t_hashs_16, t_ha16k, hash_index;
	u32 ppe_saddr_127_96, ppe_saddr_95_64, ppe_saddr_63_32, ppe_saddr_31_0;
	u32 ppe_daddr_127_96, ppe_daddr_95_64, ppe_daddr_63_32, ppe_daddr_31_0;
	u32 ipv6_sip_127_96, ipv6_sip_95_64, ipv6_sip_63_32, ipv6_sip_31_0;
	u32 ipv6_dip_127_96, ipv6_dip_95_64, ipv6_dip_63_32, ipv6_dip_31_0;
	u32 sport, dport, ppe_sportv6, ppe_dportv6;

	ipv6_sip_127_96 = key->ipv6_routing.sip0;
	ipv6_sip_95_64 = key->ipv6_routing.sip1;
	ipv6_sip_63_32 = key->ipv6_routing.sip2;
	ipv6_sip_31_0 = key->ipv6_routing.sip3;
	ipv6_dip_127_96 = key->ipv6_routing.dip0;
	ipv6_dip_95_64 = key->ipv6_routing.dip1;
	ipv6_dip_63_32 = key->ipv6_routing.dip2;
	ipv6_dip_31_0 = key->ipv6_routing.dip3;
	sport = key->ipv6_routing.sport;
	dport = key->ipv6_routing.dport;

	t_hvt_31 = ipv6_sip_31_0 ^ ipv6_dip_31_0 ^ (sport << 16 | dport);
	t_hvt_63 = ipv6_sip_63_32 ^ ipv6_dip_63_32 ^ ipv6_dip_127_96;
	t_hvt_95 = ipv6_sip_95_64 ^ ipv6_dip_95_64 ^ ipv6_sip_127_96;
	if (DFL_FOE_HASH_MODE == 1)	/* hash mode 1 */
		t_hvt_sd = (t_hvt_31 & t_hvt_63) | ((~t_hvt_31) & t_hvt_95);
	else                            /* hash mode 2 */
		t_hvt_sd = t_hvt_63 ^ (t_hvt_31 & (~t_hvt_95));

	t_hvt_sd_23 = t_hvt_sd & 0xffffff;
	t_hvt_sd_31_24 = t_hvt_sd & 0xff000000;
	t_hash_32 = t_hvt_31 ^ t_hvt_63 ^ t_hvt_95 ^ ((t_hvt_sd_23 << 8) | (t_hvt_sd_31_24 >> 24));
	t_hashs_16 = ((t_hash_32 & 0xffff0000) >> 16) ^ (t_hash_32 & 0xfffff);

	if (FOE_4TB_SIZ == 16384)
		t_ha16k = t_hashs_16 & 0x1fff;  /* FOE_16k */
	else if (FOE_4TB_SIZ == 8192)
		t_ha16k = t_hashs_16 & 0xfff;  /* FOE_8k */
	else if (FOE_4TB_SIZ == 4096)
		t_ha16k = t_hashs_16 & 0x7ff;  /* FOE_4k */
	else if (FOE_4TB_SIZ == 2048)
		t_ha16k = t_hashs_16 & 0x3ff;  /* FOE_2k */
	else
		t_ha16k = t_hashs_16 & 0x1ff;  /* FOE_1k */
	hash_index = (u32)t_ha16k * 2;

	entry = &ppe_foe_base[hash_index];
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

	if ((ipv6_sip_127_96 == ppe_saddr_127_96) && (ipv6_sip_95_64 == ppe_saddr_95_64) &&
	    (ipv6_sip_63_32 == ppe_saddr_63_32) && (ipv6_sip_31_0 == ppe_saddr_31_0) &&
	    (ipv6_dip_127_96 == ppe_daddr_127_96) && (ipv6_dip_95_64 == ppe_daddr_95_64) &&
	    (ipv6_dip_63_32 == ppe_daddr_63_32) && (ipv6_dip_31_0 == ppe_daddr_31_0) &&
	    (sport == ppe_sportv6) && (dport == ppe_dportv6)) {
		if (debug_level >= 1)
			pr_info("mib: ipv6 entry found entry idx = %d\n", hash_index);
	} else {
			hash_index = hash_index + 1;
			entry = &ppe_foe_base[hash_index];
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
			if ((ipv6_sip_127_96 == ppe_saddr_127_96) && (ipv6_sip_95_64 == ppe_saddr_95_64) &&
			    (ipv6_sip_63_32 == ppe_saddr_63_32) && (ipv6_sip_31_0 == ppe_saddr_31_0) &&
			    (ipv6_dip_127_96 == ppe_daddr_127_96) && (ipv6_dip_95_64 == ppe_daddr_95_64) &&
			    (ipv6_dip_63_32 == ppe_daddr_63_32) && (ipv6_dip_31_0 == ppe_daddr_31_0) &&
			    (sport == ppe_sportv6) && (dport == ppe_dportv6)) {
				if (debug_level >= 1)
					pr_info("mib: ipv6 entry found entry idx = %d\n", hash_index);
			} else {
				if (debug_level >= 1)
					pr_info("mib: ipv6 entry not found\n");
				return -1;
			}
	}

	return hash_index;
}
#endif

int hash_ipv4(struct foe_pri_key *key, struct foe_entry *entry, int del)
{
	u32 t_hvt_31;
	u32 t_hvt_63;
	u32 t_hvt_95;
	u32 t_hvt_sd;

	u32 t_hvt_sd_23;
	u32 t_hvt_sd_31_24;
	u32 t_hash_32;
	u32 t_hashs_16;
	u32 t_ha16k;
	u32 hash_index;
	u32 ppe_saddr, ppe_daddr, ppe_sport, ppe_dport, saddr, daddr, sport, dport;

	saddr = key->ipv4_hnapt.sip;
	daddr = key->ipv4_hnapt.dip;
	sport = key->ipv4_hnapt.sport;
	dport = key->ipv4_hnapt.dport;

	t_hvt_31 = sport << 16 | dport;
	t_hvt_63 = daddr;
	t_hvt_95 = saddr;

	/* pr_info("saddr = %x, daddr=%x, sport=%d, dport=%d\n", saddr, daddr, sport, dport); */
	if (DFL_FOE_HASH_MODE == 1)	/* hash mode 1 */
		t_hvt_sd = (t_hvt_31 & t_hvt_63) | ((~t_hvt_31) & t_hvt_95);
	else                            /* hash mode 2 */
		t_hvt_sd = t_hvt_63 ^ (t_hvt_31 & (~t_hvt_95));

	t_hvt_sd_23 = t_hvt_sd & 0xffffff;
	t_hvt_sd_31_24 = t_hvt_sd & 0xff000000;
	t_hash_32 = t_hvt_31 ^ t_hvt_63 ^ t_hvt_95 ^ ((t_hvt_sd_23 << 8) | (t_hvt_sd_31_24 >> 24));
	t_hashs_16 = ((t_hash_32 & 0xffff0000) >> 16) ^ (t_hash_32 & 0xfffff);

	if (FOE_4TB_SIZ == 16384)
		t_ha16k = t_hashs_16 & 0x1fff;  /* FOE_16k */
	else if (FOE_4TB_SIZ == 8192)
		t_ha16k = t_hashs_16 & 0xfff;  /* FOE_8k */
	else if (FOE_4TB_SIZ == 4096)
		t_ha16k = t_hashs_16 & 0x7ff;  /* FOE_4k */
	else if (FOE_4TB_SIZ == 2048)
		t_ha16k = t_hashs_16 & 0x3ff;  /* FOE_2k */
	else
		t_ha16k = t_hashs_16 & 0x1ff;  /* FOE_1k */
	hash_index = (u32)t_ha16k * 2;

	entry = &ppe_foe_base[hash_index];
	ppe_saddr = entry->ipv4_hnapt.sip;
	ppe_daddr = entry->ipv4_hnapt.dip;
	ppe_sport = entry->ipv4_hnapt.sport;
	ppe_dport = entry->ipv4_hnapt.dport;

	if (del != 1) {
		if (entry->ipv4_hnapt.bfib1.state == BIND) {
			pr_info("Hash collision, hash index +1\n");
			hash_index = hash_index + 1;
			entry = &ppe_foe_base[hash_index];
		}
		if (entry->ipv4_hnapt.bfib1.state == BIND) {
			pr_info("Hash collision can not bind\n");
			return -1;
		}
	} else if (del == 1) {
		if ((saddr == ppe_saddr) && (daddr == ppe_daddr) &&
		    (sport == ppe_sport) && (dport == ppe_dport)) {
		} else {
			hash_index = hash_index + 1;
			entry = &ppe_foe_base[hash_index];
			ppe_saddr = entry->ipv4_hnapt.sip;
			ppe_daddr = entry->ipv4_hnapt.dip;
			ppe_sport = entry->ipv4_hnapt.sport;
			ppe_dport = entry->ipv4_hnapt.dport;
			if ((saddr == ppe_saddr) && (daddr == ppe_daddr) &&
			    (sport == ppe_sport) && (dport == ppe_dport)) {
			} else {
				if (fe_feature & SEMI_AUTO_MODE)
					pr_info("hash collision hwnat can not found\n");
				else if (fe_feature & MANUAL_MODE)
					pr_info("Entry delete : Entry Not found\n");

				return -1;
			}
		}
	}
	return hash_index;
}

int hash_mib_ipv4(struct foe_pri_key *key, struct foe_entry *entry)
{
	u32 t_hvt_31;
	u32 t_hvt_63;
	u32 t_hvt_95;
	u32 t_hvt_sd;

	u32 t_hvt_sd_23;
	u32 t_hvt_sd_31_24;
	u32 t_hash_32;
	u32 t_hashs_16;
	u32 t_ha16k;
	u32 hash_index;
	u32 ppe_saddr, ppe_daddr, ppe_sport, ppe_dport, saddr, daddr, sport, dport;

	saddr = key->ipv4_hnapt.sip;
	daddr = key->ipv4_hnapt.dip;
	sport = key->ipv4_hnapt.sport;
	dport = key->ipv4_hnapt.dport;

	t_hvt_31 = sport << 16 | dport;
	t_hvt_63 = daddr;
	t_hvt_95 = saddr;

	/* pr_info("saddr = %x, daddr=%x, sport=%d, dport=%d\n", saddr, daddr, sport, dport); */
	if (DFL_FOE_HASH_MODE == 1)	/* hash mode 1 */
		t_hvt_sd = (t_hvt_31 & t_hvt_63) | ((~t_hvt_31) & t_hvt_95);
	else                            /* hash mode 2 */
		t_hvt_sd = t_hvt_63 ^ (t_hvt_31 & (~t_hvt_95));

	t_hvt_sd_23 = t_hvt_sd & 0xffffff;
	t_hvt_sd_31_24 = t_hvt_sd & 0xff000000;
	t_hash_32 = t_hvt_31 ^ t_hvt_63 ^ t_hvt_95 ^ ((t_hvt_sd_23 << 8) | (t_hvt_sd_31_24 >> 24));
	t_hashs_16 = ((t_hash_32 & 0xffff0000) >> 16) ^ (t_hash_32 & 0xfffff);

	if (FOE_4TB_SIZ == 16384)
		t_ha16k = t_hashs_16 & 0x1fff;  /* FOE_16k */
	else if (FOE_4TB_SIZ == 8192)
		t_ha16k = t_hashs_16 & 0xfff;  /* FOE_8k */
	else if (FOE_4TB_SIZ == 4096)
		t_ha16k = t_hashs_16 & 0x7ff;  /* FOE_4k */
	else if (FOE_4TB_SIZ == 2048)
		t_ha16k = t_hashs_16 & 0x3ff;  /* FOE_2k */
	else
		t_ha16k = t_hashs_16 & 0x1ff;  /* FOE_1k */
	hash_index = (u32)t_ha16k * 2;

	entry = &ppe_foe_base[hash_index];
	ppe_saddr = entry->ipv4_hnapt.sip;
	ppe_daddr = entry->ipv4_hnapt.dip;
	ppe_sport = entry->ipv4_hnapt.sport;
	ppe_dport = entry->ipv4_hnapt.dport;

	if ((saddr == ppe_saddr) && (daddr == ppe_daddr) &&
	    (sport == ppe_sport) && (dport == ppe_dport)) {
		if (debug_level >= 1)
			pr_info("mib: ipv4 entry entry : %d\n", hash_index);
	} else {
			hash_index = hash_index + 1;
			entry = &ppe_foe_base[hash_index];
			ppe_saddr = entry->ipv4_hnapt.sip;
			ppe_daddr = entry->ipv4_hnapt.dip;
			ppe_sport = entry->ipv4_hnapt.sport;
			ppe_dport = entry->ipv4_hnapt.dport;
			if ((saddr == ppe_saddr) && (daddr == ppe_daddr) &&
			    (sport == ppe_sport) && (dport == ppe_dport)) {
				if (debug_level >= 1)
					pr_info("mib: ipv4 entry entry : %d\n", hash_index);
			} else {
				if (debug_level >= 1)
					pr_info("mib: ipv4 entry not found\n");
				return -1;
			}
			return hash_index;
	}

	return hash_index;
}

int get_ppe_entry_idx(struct foe_pri_key *key, struct foe_entry *entry, int del)
{
	if ((key->pkt_type) == IPV4_NAPT)
		return hash_ipv4(key, entry, del);
#if defined(CONFIG_RA_HW_NAT_IPV6)
	else if ((key->pkt_type) == IPV6_ROUTING)
		return hash_ipv6(key, entry, del);
#endif
	else
		return -1;
}

int get_mib_entry_idx(struct foe_pri_key *key, struct foe_entry *entry)
{
	if ((key->pkt_type) == IPV4_NAPT)
		return hash_mib_ipv4(key, entry);
#if defined(CONFIG_RA_HW_NAT_IPV6)
	else if ((key->pkt_type) == IPV6_ROUTING)
		return hash_mib_ipv6(key, entry);
#endif
	else
		return -1;
}
EXPORT_SYMBOL(get_mib_entry_idx);

