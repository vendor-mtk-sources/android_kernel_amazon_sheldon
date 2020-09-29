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
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/if_vlan.h>
#include <net/ipv6.h>
#include <net/ip.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/inetdevice.h>
#include <net/rtnetlink.h>
#include <net/netevent.h>
#include <linux/platform_device.h>
#include <net/ra_nat.h>
#include "foe_fdb.h"
#include "frame_engine.h"
#include "util.h"
#include "hwnat_ioctl.h"
#include "hwnat_define.h"
#include "hwnat_config.h"
#include "hnat_dbg_proc.h"

struct timer_list hwnat_clear_entry_timer;
unsigned int hnat_chip_name;
EXPORT_SYMBOL(hnat_chip_name);
unsigned int fe_feature;
EXPORT_SYMBOL(fe_feature);
unsigned int dbg_cpu_reason_cnt[32];
EXPORT_SYMBOL(dbg_cpu_reason_cnt);
int hwnat_dbg_entry;
EXPORT_SYMBOL(hwnat_dbg_entry);
int get_brlan;
u32 br_netmask;
u32 br0_ip;
char br0_mac_address[6];

static void hwnat_clear_entry(unsigned long data)
{
	pr_info("HW_NAT work normally\n");
	reg_modify_bits(PPE_FOE_CFG, FWD_CPU_BUILD_ENTRY, 4, 2);
	/* del_timer_sync(&hwnat_clear_entry_timer); */
}

#include "mcast_tbl.h"

/*#include "../../../drivers/net/raeth/ra_ioctl.h"*/
u8 USE_3T_UDP_FRAG;
struct foe_entry *ppe_foe_base;
EXPORT_SYMBOL(ppe_foe_base);
dma_addr_t ppe_phy_foe_base;
struct ps_entry *ppe_ps_base;
dma_addr_t ppe_phy_ps_base;
struct mib_entry *ppe_mib_base;
dma_addr_t ppe_phy_mib_base;

struct pkt_parse_result ppe_parse_result;
struct hwnat_ac_args ac_info[64];	/* 1 for LAN, 2 for WAN */
EXPORT_SYMBOL(ac_info);

int DP_GMAC1;
int DP_GMAC2;

/* #define DSCP_REMARK_TEST */
/* #define PREBIND_TEST */
#define DD \
{\
pr_info("%s %d\n", __func__, __LINE__); \
}

/*HWNAT IPI*/
/*unsigned int ipidbg[NR_CPUS][10];*/
/*unsigned int ipidbg2[NR_CPUS][10];*/
/*extern int32_t HnatIPIExtIfHandler(struct sk_buff * skb);*/
/*extern int32_t HnatIPIForceCPU(struct sk_buff * skb);*/
/*extern int HnatIPIInit();*/
/*extern int HnatIPIDeInit();*/

uint16_t IS_IF_PCIE_WLAN(struct sk_buff *skb)
{
	if (IS_MAGIC_TAG_PROTECT_VALID_HEAD(skb))
		return IS_IF_PCIE_WLAN_HEAD(skb);
	else if (IS_MAGIC_TAG_PROTECT_VALID_TAIL(skb))
		return IS_IF_PCIE_WLAN_TAIL(skb);
	else if (IS_MAGIC_TAG_PROTECT_VALID_CB(skb))
		return IS_IF_PCIE_WLAN_CB(skb);
	else
		return 0;
}

uint16_t IS_IF_PCIE_WLAN_RX(struct sk_buff *skb)
{
	return IS_IF_PCIE_WLAN_HEAD(skb);
}

uint16_t IS_MAGIC_TAG_PROTECT_VALID(struct sk_buff *skb)
{
	if (IS_MAGIC_TAG_PROTECT_VALID_HEAD(skb))
		return IS_MAGIC_TAG_PROTECT_VALID_HEAD(skb);
	else if (IS_MAGIC_TAG_PROTECT_VALID_TAIL(skb))
		return IS_MAGIC_TAG_PROTECT_VALID_TAIL(skb);
	else if (IS_MAGIC_TAG_PROTECT_VALID_CB(skb))
		return IS_MAGIC_TAG_PROTECT_VALID_CB(skb);
	else
		return 0;
}

unsigned char *FOE_INFO_START_ADDR(struct sk_buff *skb)
{
	if (IS_MAGIC_TAG_PROTECT_VALID_HEAD(skb))
		return FOE_INFO_START_ADDR_HEAD(skb);
	else if (IS_MAGIC_TAG_PROTECT_VALID_TAIL(skb))
		return FOE_INFO_START_ADDR_TAIL(skb);
	else if (IS_MAGIC_TAG_PROTECT_VALID_CB(skb))
		return FOE_INFO_START_ADDR_CB(skb);

	pr_info("!!!FOE_INFO_START_ADDR Error!!!!\n");
	return FOE_INFO_START_ADDR_HEAD(skb);
}

void FOE_INFO_DUMP(struct sk_buff *skb)
{
	pr_info("FOE_INFO_START_ADDR(skb) =%p\n", FOE_INFO_START_ADDR(skb));
	pr_info("FOE_TAG_PROTECT(skb) =%x\n", FOE_TAG_PROTECT(skb));
	pr_info("FOE_ENTRY_NUM(skb) =%x\n", FOE_ENTRY_NUM(skb));
	pr_info("FOE_ALG(skb) =%x\n", FOE_ALG(skb));
	pr_info("FOE_AI(skb) =%x\n", FOE_AI(skb));
	pr_info("FOE_SP(skb) =%x\n", FOE_SP(skb));
	pr_info("FOE_MAGIC_TAG(skb) =%x\n", FOE_MAGIC_TAG(skb));
	if (fe_feature & WARP_WHNAT) {
		pr_info("FOE_WDMA_ID(skb) =%x\n", FOE_WDMA_ID(skb));
		pr_info("FOE_RX_ID(skb) =%x\n", FOE_RX_ID(skb));
		pr_info("FOE_WC_ID(skb) =%x\n", FOE_WC_ID(skb));
		pr_info("FOE_FOE_BSS_IDIF(skb) =%x\n", FOE_BSS_ID(skb));
	}
}

void FOE_INFO_DUMP_TAIL(struct sk_buff *skb)
{
	pr_info("FOE_INFO_START_ADDR_TAIL(skb) =%p\n", FOE_INFO_START_ADDR_TAIL(skb));
	pr_info("FOE_TAG_PROTECT_TAIL(skb) =%x\n", FOE_TAG_PROTECT_TAIL(skb));
	pr_info("FOE_ENTRY_NUM_TAIL(skb) =%x\n", FOE_ENTRY_NUM_TAIL(skb));
	pr_info("FOE_ALG_TAIL(skb) =%x\n", FOE_ALG_TAIL(skb));
	pr_info("FOE_AI_TAIL(skb) =%x\n", FOE_AI_TAIL(skb));
	pr_info("FOE_SP_TAIL(skb) =%x\n", FOE_SP_TAIL(skb));
	pr_info("FOE_MAGIC_TAG_TAIL(skb) =%x\n", FOE_MAGIC_TAG_TAIL(skb));
	if (fe_feature & WARP_WHNAT) {
		pr_info("FOE_WDMA_ID_TAIL(skb) =%x\n", FOE_WDMA_ID_TAIL(skb));
		pr_info("FOE_RX_ID_TAIL(skb) =%x\n", FOE_RX_ID_TAIL(skb));
		pr_info("FOE_WC_ID_TAIL(skb) =%x\n", FOE_WC_ID_TAIL(skb));
		pr_info("FOE_FOE_BSS_IDIF_TAIL(skb) =%x\n", FOE_BSS_ID_TAIL(skb));
	}
}

int hwnat_info_region;
uint16_t tx_decide_which_region(struct sk_buff *skb)
{
	if (IS_MAGIC_TAG_PROTECT_VALID_HEAD(skb) && IS_SPACE_AVAILABLE_HEAD(skb)) {
		FOE_INFO_START_ADDR(skb);
		FOE_TAG_PROTECT(skb) = FOE_TAG_PROTECT_HEAD(skb);
		FOE_ENTRY_NUM_MSB(skb) = FOE_ENTRY_NUM_MSB_HEAD(skb);
		FOE_ENTRY_NUM_LSB(skb) = FOE_ENTRY_NUM_LSB_HEAD(skb);
		FOE_ALG(skb) = FOE_ALG_HEAD(skb);
		FOE_AI(skb) = FOE_AI_HEAD(skb);
		FOE_SP(skb) = FOE_SP_HEAD(skb);
		FOE_MAGIC_TAG(skb) = FOE_MAGIC_TAG_HEAD(skb);
		if (fe_feature & WARP_WHNAT) {
			FOE_WDMA_ID(skb) = FOE_WDMA_ID_HEAD(skb);
			FOE_RX_ID(skb) = FOE_RX_ID_HEAD(skb);
			FOE_WC_ID(skb) = FOE_WC_ID_HEAD(skb);
			FOE_BSS_ID(skb) = FOE_BSS_ID_HEAD(skb);
		}
		hwnat_info_region = USE_HEAD_ROOM;
		return USE_HEAD_ROOM;	/* use headroom */
	} else if (IS_MAGIC_TAG_PROTECT_VALID_TAIL(skb) && IS_SPACE_AVAILABLE_TAIL(skb)) {
		FOE_INFO_START_ADDR(skb);
		FOE_TAG_PROTECT(skb) = FOE_TAG_PROTECT_TAIL(skb);
		FOE_ENTRY_NUM_MSB(skb) = FOE_ENTRY_NUM_MSB_TAIL(skb);
		FOE_ENTRY_NUM_LSB(skb) = FOE_ENTRY_NUM_LSB_TAIL(skb);
		FOE_ALG(skb) = FOE_ALG_TAIL(skb);
		FOE_AI(skb) = FOE_AI_TAIL(skb);
		FOE_SP(skb) = FOE_SP_TAIL(skb);

		FOE_MAGIC_TAG(skb) = FOE_MAGIC_TAG_TAIL(skb);
		if (fe_feature & WARP_WHNAT) {
			FOE_WDMA_ID(skb) = FOE_WDMA_ID_TAIL(skb);
			FOE_RX_ID(skb) = FOE_RX_ID_TAIL(skb);
			FOE_WC_ID(skb) = FOE_WC_ID_TAIL(skb);
			FOE_BSS_ID(skb) = FOE_BSS_ID_TAIL(skb);
		}
		hwnat_info_region = USE_TAIL_ROOM;
		return USE_TAIL_ROOM;	/* use tailroom */
	}
	hwnat_info_region = ALL_INFO_ERROR;
	return ALL_INFO_ERROR;
}

uint16_t remove_vlan_tag(struct sk_buff *skb)
{
	struct ethhdr *eth;
	struct vlan_ethhdr *veth;
	u16 vir_if_idx;

	if (skb_vlan_tag_present(skb)) { /*hw vlan rx enable*/
		vir_if_idx = skb_vlan_tag_get(skb) & 0x3fff;
		skb->vlan_proto = 0;
		skb->vlan_tci = 0;
		return vir_if_idx;
	}

	veth = (struct vlan_ethhdr *)skb_mac_header(skb);
	/* something wrong */
	if ((veth->h_vlan_proto != htons(ETH_P_8021Q)) && (veth->h_vlan_proto != 0x5678)) {
		/* if (pr_debug_ratelimited()) */
		pr_info("HNAT: Reentry packet is untagged frame?\n");
		return 65535;
	}
	/*we just want to get vid*/
	vir_if_idx = ntohs(veth->h_vlan_TCI) & 0x3fff;

	if (skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *new_skb;

		new_skb = skb_copy(skb, GFP_ATOMIC);
		kfree_skb(skb);
		if (!new_skb)
			return 65535;
		skb = new_skb;
		/*logic error*/
		/* kfree_skb(new_skb); */
	}

	/* remove VLAN tag */
	skb->data = skb_mac_header(skb);
	skb->mac_header = skb->mac_header + VLAN_HLEN;
	memmove(skb_mac_header(skb), skb->data, ETH_ALEN * 2);

	skb_pull(skb, VLAN_HLEN);
	skb->data += ETH_HLEN;	/* pointer to layer3 header */
	eth = (struct ethhdr *)skb_mac_header(skb);

	skb->protocol = eth->h_proto;

	return vir_if_idx;
}

static int foe_alloc_tbl(u32 num_of_entry, struct device *dev)
{
	u32 foe_tbl_size;
	u32 ps_tbl_size;

	struct foe_entry *entry;
	int boundary_entry_offset[7] = { 12, 25, 38, 51, 76, 89, 102 };
	/*these entries are bad every 128 entries */
	int entry_base = 0;
	int bad_entry, i, j;
	dma_addr_t ppe_phy_foebase_tmp;
	u32 mib_tbl_size;

	foe_tbl_size = num_of_entry * sizeof(struct foe_entry);
	ppe_phy_foebase_tmp = reg_read(PPE_FOE_BASE);

	if (ppe_phy_foebase_tmp) {
		ppe_phy_foe_base = ppe_phy_foebase_tmp;
		ppe_foe_base = (struct foe_entry *)ppe_virt_foe_base_tmp;
		pr_info("***ppe_foe_base = %p\n", ppe_foe_base);
		pr_info("***PpeVirtFoeBase_tmp = %p\n", ppe_virt_foe_base_tmp);
		if (!ppe_foe_base) {
			pr_info("PPE_FOE_BASE=%x\n", reg_read(PPE_FOE_BASE));
			pr_info("ppe_foe_base ioremap fail!!!!\n");
			return 0;
		}
	} else {
		if (hnat_chip_name & (MT7622_HWNAT | LEOPARD_HWNAT)) {
			ppe_foe_base =
			    dma_alloc_coherent(dev, foe_tbl_size, &ppe_phy_foe_base, GFP_KERNEL);
		} else {
			ppe_foe_base = dma_alloc_coherent(NULL, foe_tbl_size, &ppe_phy_foe_base, GFP_KERNEL);
		}

		ppe_virt_foe_base_tmp = ppe_foe_base;
		pr_info("init PpeVirtFoeBase_tmp = %p\n", ppe_virt_foe_base_tmp);
		pr_info("init ppe_foe_base = %p\n", ppe_foe_base);

		if (!ppe_foe_base) {
			pr_info("first ppe_phy_foe_base fail\n");
			return 0;
		}
	}

	if (!ppe_foe_base) {
		pr_info("ppe_foe_base== NULL\n");
		return 0;
	}

	reg_write(PPE_FOE_BASE, ppe_phy_foe_base);
	memset(ppe_foe_base, 0, foe_tbl_size);

	if ((fe_feature & HNAT_IPV6) && (hnat_chip_name & MT7621_HWNAT)) {
		for (i = 0; entry_base < num_of_entry; i++) {
			/* set bad entries as static */
			for (j = 0; j < 7; j++) {
				bad_entry = entry_base + boundary_entry_offset[j];
				entry = &ppe_foe_base[bad_entry];
				entry->udib1.sta = 1;
			}
			entry_base = (i + 1) * 128;
		}
	}

	if (fe_feature & PACKET_SAMPLING) {
		ps_tbl_size = num_of_entry * sizeof(struct ps_entry);

		ppe_ps_base = dma_alloc_coherent(dev, ps_tbl_size, &ppe_phy_ps_base, GFP_KERNEL);

		if (!ppe_ps_base)
			return 0;
		reg_write(PS_TB_BASE, ppe_phy_ps_base);
		memset(ppe_ps_base, 0, foe_tbl_size);
	}
	if (fe_feature & PPE_MIB) {
		mib_tbl_size = num_of_entry * sizeof(struct mib_entry);
		pr_info("num_of_entry: foe_tbl_size = %d\n", foe_tbl_size);
		ppe_mib_base = dma_alloc_coherent(dev, mib_tbl_size, &ppe_phy_mib_base, GFP_KERNEL);
		if (!ppe_mib_base) {
			pr_info("PPE MIB allocate memory fail");
			return 0;
		}
		pr_info("ppe_mib_base = %p\n",  ppe_mib_base);
		pr_info("num_of_entry = %u\n",  num_of_entry);
		pr_info("mib_tbl_size = %d\n",  mib_tbl_size);
		reg_write(MIB_TB_BASE, ppe_phy_mib_base);
		memset(ppe_mib_base, 0, mib_tbl_size);
	}

	return 1;
}

static uint8_t *show_cpu_reason(struct sk_buff *skb)
{
	static u8 buf[32];

	switch (FOE_AI(skb)) {
	case TTL_0:
		return "IPv4(IPv6) TTL(hop limit)\n";
	case HAS_OPTION_HEADER:
		return "Ipv4(IPv6) has option(extension) header\n";
	case NO_FLOW_IS_ASSIGNED:
		return "No flow is assigned\n";
	case IPV4_WITH_FRAGMENT:
		return "IPv4 HNAT doesn't support IPv4 /w fragment\n";
	case IPV4_HNAPT_DSLITE_WITH_FRAGMENT:
		return "IPv4 HNAPT/DS-Lite doesn't support IPv4 /w fragment\n";
	case IPV4_HNAPT_DSLITE_WITHOUT_TCP_UDP:
		return "IPv4 HNAPT/DS-Lite can't find TCP/UDP sport/dport\n";
	case IPV6_5T_6RD_WITHOUT_TCP_UDP:
		return "IPv6 5T-route/6RD can't find TCP/UDP sport/dport\n";
	case TCP_FIN_SYN_RST:
		return "Ingress packet is TCP fin/syn/rst\n";
	case UN_HIT:
		return "FOE Un-hit\n";
	case HIT_UNBIND:
		return "FOE Hit unbind\n";
	case HIT_UNBIND_RATE_REACH:
		return "FOE Hit unbind & rate reach\n";
	case HIT_BIND_TCP_FIN:
		return "Hit bind PPE TCP FIN entry\n";
	case HIT_BIND_TTL_1:
		return "Hit bind PPE entry and TTL(hop limit) = 1 and TTL(hot limit) - 1\n";
	case HIT_BIND_WITH_VLAN_VIOLATION:
		return "Hit bind and VLAN replacement violation\n";
	case HIT_BIND_KEEPALIVE_UC_OLD_HDR:
		return "Hit bind and keep alive with unicast old-header packet\n";
	case HIT_BIND_KEEPALIVE_MC_NEW_HDR:
		return "Hit bind and keep alive with multicast new-header packet\n";
	case HIT_BIND_KEEPALIVE_DUP_OLD_HDR:
		return "Hit bind and keep alive with duplicate old-header packet\n";
	case HIT_BIND_FORCE_TO_CPU:
		return "FOE Hit bind & force to CPU\n";
	case HIT_BIND_EXCEED_MTU:
		return "Hit bind and exceed MTU\n";
	case HIT_BIND_MULTICAST_TO_CPU:
		return "Hit bind multicast packet to CPU\n";
	case HIT_BIND_MULTICAST_TO_GMAC_CPU:
		return "Hit bind multicast packet to GMAC & CPU\n";
	case HIT_PRE_BIND:
		return "Pre bind\n";
	}

	sprintf(buf, "CPU Reason Error - %X\n", FOE_AI(skb));
	return buf;
}

#if (0)
uint32_t foe_dump_pkt_tx(struct sk_buff *skb)
{
	struct foe_entry *entry = &ppe_foe_base[FOE_ENTRY_NUM(skb)];
	int i;

	NAT_PRINT("\nTx===<FOE_Entry=%d>=====\n", FOE_ENTRY_NUM(skb));
	pr_info("Tx handler skb_headroom size = %u, skb->head = %p, skb->data = %p\n",
		skb_headroom(skb), skb->head, skb->data);
	for (i = 0; i < skb_headroom(skb); i++) {
		pr_info("tx_skb->head[%d]=%x\n", i, *(unsigned char *)(skb->head + i));
		/* pr_info("%02X-",*((unsigned char*)i)); */
	}

	NAT_PRINT("==================================\n");
	return 1;
}
#endif

uint32_t foe_dump_pkt(struct sk_buff *skb)
{
	struct foe_entry *entry = &ppe_foe_base[FOE_ENTRY_NUM(skb)];

	NAT_PRINT("\nRx===<FOE_Entry=%d>=====\n", FOE_ENTRY_NUM(skb));
	NAT_PRINT("RcvIF=%s\n", skb->dev->name);
	NAT_PRINT("FOE_Entry=%d\n", FOE_ENTRY_NUM(skb));
	NAT_PRINT("CPU Reason=%s", show_cpu_reason(skb));
	NAT_PRINT("ALG=%d\n", FOE_ALG(skb));
	NAT_PRINT("SP=%d\n", FOE_SP(skb));

	/* some special alert occurred, so entry_num is useless (just skip it) */
	if (FOE_ENTRY_NUM(skb) == 0x3fff)
		return 1;

	/* PPE: IPv4 packet=IPV4_HNAT IPv6 packet=IPV6_ROUTE */
	if (IS_IPV4_GRP(entry)) {
		NAT_PRINT("Information Block 1=%x\n", entry->ipv4_hnapt.info_blk1);
		NAT_PRINT("SIP=%s\n", ip_to_str(entry->ipv4_hnapt.sip));
		NAT_PRINT("DIP=%s\n", ip_to_str(entry->ipv4_hnapt.dip));
		NAT_PRINT("SPORT=%d\n", entry->ipv4_hnapt.sport);
		NAT_PRINT("DPORT=%d\n", entry->ipv4_hnapt.dport);
		NAT_PRINT("Information Block 2=%x\n", entry->ipv4_hnapt.info_blk2);
		NAT_PRINT("State = %s, proto = %s\n",
			  entry->bfib1.state ==
			  0 ? "Invalid" : entry->bfib1.state ==
			  1 ? "Unbind" : entry->bfib1.state ==
			  2 ? "BIND" : entry->bfib1.state ==
			  3 ? "FIN" : "Unknown", entry->ipv4_hnapt.bfib1.udp ==
			  0 ? "TCP" : entry->ipv4_hnapt.bfib1.udp ==
			  1 ? "UDP" : "Unknown");
	}
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV6_GRP(entry)) {
			NAT_PRINT("Information Block 1=%x\n", entry->ipv6_5t_route.info_blk1);
			NAT_PRINT("IPv6_SIP=%08X:%08X:%08X:%08X\n",
				  entry->ipv6_5t_route.ipv6_sip0,
				  entry->ipv6_5t_route.ipv6_sip1,
				  entry->ipv6_5t_route.ipv6_sip2, entry->ipv6_5t_route.ipv6_sip3);
			NAT_PRINT("IPv6_DIP=%08X:%08X:%08X:%08X\n",
				  entry->ipv6_5t_route.ipv6_dip0,
				  entry->ipv6_5t_route.ipv6_dip1,
				  entry->ipv6_5t_route.ipv6_dip2, entry->ipv6_5t_route.ipv6_dip3);
			if (IS_IPV6_FLAB_EBL()) {
				NAT_PRINT("Flow Label=%08X\n", (entry->ipv6_5t_route.sport << 16) |
					  (entry->ipv6_5t_route.dport));
			} else {
				NAT_PRINT("SPORT=%d\n", entry->ipv6_5t_route.sport);
				NAT_PRINT("DPORT=%d\n", entry->ipv6_5t_route.dport);
			}
			NAT_PRINT("Information Block 2=%x\n", entry->ipv6_5t_route.info_blk2);
			NAT_PRINT("State = %s, proto = %s\n",
				  entry->bfib1.state ==
				  0 ? "Invalid" : entry->bfib1.state ==
				  1 ? "Unbind" : entry->bfib1.state ==
				  2 ? "BIND" : entry->bfib1.state ==
				  3 ? "FIN" : "Unknown", entry->ipv6_5t_route.bfib1.udp ==
				  0 ? "TCP" : entry->ipv6_5t_route.bfib1.udp ==
				  1 ? "UDP" : "Unknown");
		}
	}
	if ((!IS_IPV4_GRP(entry)) && (!(IS_IPV6_GRP(entry))))
		NAT_PRINT("unknown Pkt_type=%d\n", entry->bfib1.pkt_type);

	NAT_PRINT("==================================\n");
	return 1;
}

uint32_t hnat_cpu_reason_cnt(struct sk_buff *skb)
{
	switch (FOE_AI(skb)) {
	case TTL_0:
		dbg_cpu_reason_cnt[0]++;
		return 0;
	case HAS_OPTION_HEADER:
		dbg_cpu_reason_cnt[1]++;
		return 0;
	case NO_FLOW_IS_ASSIGNED:
		dbg_cpu_reason_cnt[2]++;
		return 0;
	case IPV4_WITH_FRAGMENT:
		dbg_cpu_reason_cnt[3]++;
		return 0;
	case IPV4_HNAPT_DSLITE_WITH_FRAGMENT:
		dbg_cpu_reason_cnt[4]++;
		return 0;
	case IPV4_HNAPT_DSLITE_WITHOUT_TCP_UDP:
		dbg_cpu_reason_cnt[5]++;
		return 0;
	case IPV6_5T_6RD_WITHOUT_TCP_UDP:
		dbg_cpu_reason_cnt[6]++;
		return 0;
	case TCP_FIN_SYN_RST:
		dbg_cpu_reason_cnt[7]++;
		return 0;
	case UN_HIT:
		dbg_cpu_reason_cnt[8]++;
		return 0;
	case HIT_UNBIND:
		dbg_cpu_reason_cnt[9]++;
		return 0;
	case HIT_UNBIND_RATE_REACH:
		dbg_cpu_reason_cnt[10]++;
		return 0;
	case HIT_BIND_TCP_FIN:
		dbg_cpu_reason_cnt[11]++;
		return 0;
	case HIT_BIND_TTL_1:
		dbg_cpu_reason_cnt[12]++;
		return 0;
	case HIT_BIND_WITH_VLAN_VIOLATION:
		dbg_cpu_reason_cnt[13]++;
		return 0;
	case HIT_BIND_KEEPALIVE_UC_OLD_HDR:
		dbg_cpu_reason_cnt[14]++;
		return 0;
	case HIT_BIND_KEEPALIVE_MC_NEW_HDR:
		dbg_cpu_reason_cnt[15]++;
		return 0;
	case HIT_BIND_KEEPALIVE_DUP_OLD_HDR:
		dbg_cpu_reason_cnt[16]++;
		return 0;
	case HIT_BIND_FORCE_TO_CPU:
		dbg_cpu_reason_cnt[17]++;
		return 0;
	case HIT_BIND_EXCEED_MTU:
		dbg_cpu_reason_cnt[18]++;
		return 0;
	case HIT_BIND_MULTICAST_TO_CPU:
		dbg_cpu_reason_cnt[19]++;
		return 0;
	case HIT_BIND_MULTICAST_TO_GMAC_CPU:
		dbg_cpu_reason_cnt[20]++;
		return 0;
	case HIT_PRE_BIND:
		dbg_cpu_reason_cnt[21]++;
		return 0;
	}

	return 0;
}

int get_bridge_info(void)
{
	struct net_device *br0_dev;
	struct in_device *br0_in_dev;

	if (fe_feature & HNAT_OPENWRT)
		br0_dev = dev_get_by_name(&init_net, "br-lan");
	else
		br0_dev = dev_get_by_name(&init_net, "br0");

	if (!br0_dev) {
		pr_info("br0_dev = NULL\n");
		return 1;
	}
	br0_in_dev = in_dev_get(br0_dev);
	if (!br0_in_dev) {
		pr_info("br0_in_dev = NULL\n");
		return 1;
	}
	br_netmask = ntohl(br0_in_dev->ifa_list->ifa_mask);
	br0_ip = ntohl(br0_in_dev->ifa_list->ifa_address);
	if (br0_dev)
		dev_put(br0_dev);

	if (br0_in_dev)
		in_dev_put(br0_in_dev);
	else
		pr_info("br0_in_dev = NULL\n");

	pr_info("br0_ip = %x\n", br0_ip);
	pr_info("br_netmask = %x\n", br_netmask);
	get_brlan = 1;

	return 0;
}

int bridge_lan_subnet(struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	u32 daddr = 0;
	u32 saddr = 0;
	u32 eth_type;
	u32 ppp_tag = 0;
	struct vlan_hdr *vh = NULL;
	struct ethhdr *eth = NULL;
	struct pppoe_hdr *peh = NULL;
	u8 vlan1_gap = 0;
	u8 vlan2_gap = 0;
	u8 pppoe_gap = 0;
	int ret;
	struct vlan_hdr pseudo_vhdr;

	eth = (struct ethhdr *)skb->data;
	if (is_multicast_ether_addr(&eth->h_dest[0]))
		return 0;
	eth_type = eth->h_proto;
	if ((eth_type == htons(ETH_P_8021Q)) ||
	    (((eth_type) & 0x00FF) == htons(ETH_P_8021Q)) || hwnat_vlan_tx_tag_present(skb)) {
	if (fe_feature & HNAT_VLAN_TX) {
		pseudo_vhdr.h_vlan_TCI = htons(hwnat_vlan_tag_get(skb));
		pseudo_vhdr.h_vlan_encapsulated_proto = eth->h_proto;
		vh = (struct vlan_hdr *)&pseudo_vhdr;
		vlan1_gap = VLAN_HLEN;
	} else {
		vlan1_gap = VLAN_HLEN;
		vh = (struct vlan_hdr *)(skb->data + ETH_HLEN);
	}

		/* VLAN + PPPoE */
		if (ntohs(vh->h_vlan_encapsulated_proto) == ETH_P_PPP_SES) {
			pppoe_gap = 8;
			eth_type = vh->h_vlan_encapsulated_proto;
			/* Double VLAN = VLAN + VLAN */
		} else if ((vh->h_vlan_encapsulated_proto == htons(ETH_P_8021Q)) ||
			   ((vh->h_vlan_encapsulated_proto) & 0x00FF) == htons(ETH_P_8021Q)) {
			vlan2_gap = VLAN_HLEN;
			vh = (struct vlan_hdr *)(skb->data + ETH_HLEN + VLAN_HLEN);
			/* VLAN + VLAN + PPPoE */
			if (ntohs(vh->h_vlan_encapsulated_proto) == ETH_P_PPP_SES) {
				pppoe_gap = 8;
				eth_type = vh->h_vlan_encapsulated_proto;
			} else {
				eth_type = vh->h_vlan_encapsulated_proto;
			}
		}
	} else if (ntohs(eth_type) == ETH_P_PPP_SES) {
		/* PPPoE + IP */
		pppoe_gap = 8;
		peh = (struct pppoe_hdr *)(skb->data + ETH_HLEN + vlan1_gap);
		ppp_tag = peh->tag[0].tag_type;
	}

	if (get_brlan == 0) {
		ret = get_bridge_info(); /*return 1 br0 get fail*/
		if (ret == 1)
			return 0;
	}
	/* set layer4 start addr */
	if ((eth_type == htons(ETH_P_IP)) || (eth_type == htons(ETH_P_PPP_SES) && ppp_tag == htons(PPP_IP))) {
		iph = (struct iphdr *)(skb->data + ETH_HLEN + vlan1_gap + vlan2_gap + pppoe_gap);
		daddr = ntohl(iph->daddr);
		saddr = ntohl(iph->saddr);
	}

	if (((br0_ip & br_netmask) == (daddr & br_netmask)) &&
	    ((daddr & br_netmask) == (saddr & br_netmask)))
		return 1;
	return 0;
}

int bridge_short_cut_rx(struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	u32 daddr;
	int ret;

	if (get_brlan == 0) {
		ret = get_bridge_info(); /*return 1 get br0 fail*/
		if (ret == 1)
			return 0;
	}

	iph = (struct iphdr *)(skb->data);
	daddr = ntohl(iph->daddr);
	if ((br0_ip & br_netmask) == (daddr & br_netmask))
		return 1;
	else
		return 0;
}

/* push different VID for WiFi pseudo interface or USB external NIC */
uint32_t ppe_extif_rx_handler(struct sk_buff *skb)
{
	u16 vir_if_idx = 0;
	int i = 0;
	int dev_match = 0;
	struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);

	if (fe_feature & WIFI_HNAT) {
		/* PPE can only handle IPv4/IPv6/PPP packets */
		if (((skb->protocol != htons(ETH_P_8021Q)) &&
		     (skb->protocol != htons(ETH_P_IP)) && (skb->protocol != htons(ETH_P_IPV6)) &&
		     (skb->protocol != htons(ETH_P_PPP_SES)) && (skb->protocol != htons(ETH_P_PPP_DISC))) ||
		    is_multicast_ether_addr(&eth->h_dest[0])) {
			return 1;
		}

		skb_set_network_header(skb, 0);

		if (fe_feature & WLAN_OPTIMIZE) {
			if (bridge_short_cut_rx(skb))
				return 1;	/* Bridge ==> sw path (rps) */
		}

		for (i = 0; i < MAX_IF_NUM; i++) {
			if (dst_port[i] == skb->dev) {
				vir_if_idx = i;
				dev_match = 1;
				/* pr_info("%s : Interface=%s, vir_if_idx=%x\n", __func__, skb->dev, vir_if_idx); */
				break;
			}
		}
		if (dev_match == 0) {
			if (debug_level >= 1)
				pr_info("%s UnKnown Interface, vir_if_idx=%x\n", __func__, vir_if_idx);
			return 1;
		}
		/* push vlan tag to stand for actual incoming interface, */
		/* so HNAT module can know the actual incoming interface from vlan id. */
		skb_push(skb, ETH_HLEN);/* pointer to layer2 header before calling hard_start_xmit */
		skb->dev = dst_port[DP_GMAC1];	/* we use GMAC1 to send the packet to PPE */
		if (fe_feature & HNAT_WLAN_QOS)
			set_qid(skb);
		skb->vlan_proto = htons(ETH_P_8021Q);
		if (fe_feature & HNAT_VLAN_TX) {
			skb->vlan_tci |= VLAN_TAG_PRESENT;
			skb->vlan_tci |= vir_if_idx;
		} else {
			skb = vlan_insert_tag(skb, skb->vlan_proto, vir_if_idx);
		}
		/* redirect to PPE */
		FOE_AI_HEAD(skb) = UN_HIT;
		FOE_AI_TAIL(skb) = UN_HIT;
		FOE_TAG_PROTECT_HEAD(skb) = TAG_PROTECT;
		FOE_TAG_PROTECT_TAIL(skb) = TAG_PROTECT;
		FOE_MAGIC_TAG_HEAD(skb) = FOE_MAGIC_PPE;
		FOE_MAGIC_TAG_TAIL(skb) = FOE_MAGIC_PPE;

		if (fe_feature & HNAT_WLAN_QOS) {
			/*if (debug_level >= 2)*/
				/*pr_info("skb->dev = %s\n", skb->dev);*/
			if ((!skb->dev) || ((skb->dev != dst_port[DP_GMAC2]) &&
					    (skb->dev != dst_port[DP_GMAC1])))
				skb->dev = dst_port[DP_GMAC1];	/* we use GMAC1 to send the packet to PPE */
		}
		dev_queue_xmit(skb);
		return 0;
	} else {
		return 1;
	}
}

uint32_t ppe_extif_pingpong_handler(struct sk_buff *skb)
{
	struct ethhdr *eth = NULL;
	u16 vir_if_idx = 0;
	struct net_device *dev;

	if (fe_feature & WIFI_HNAT) {
		vir_if_idx = remove_vlan_tag(skb);

		/* recover to right incoming interface */
		if (vir_if_idx < MAX_IF_NUM && dst_port[vir_if_idx]) {
			skb->dev = dst_port[vir_if_idx];
		} else {
			if (debug_level >= 1)
				pr_info("%s : HNAT: unknown interface (vir_if_idx=%d)\n", __func__, vir_if_idx);
			return 1;
		}

		eth = (struct ethhdr *)skb_mac_header(skb);

		if (eth->h_dest[0] & 1) {
			if (ether_addr_equal(eth->h_dest, skb->dev->broadcast) == 0)
				skb->pkt_type = PACKET_BROADCAST;
			else
				skb->pkt_type = PACKET_MULTICAST;
		} else {
			skb->pkt_type = PACKET_OTHERHOST;
			for (vir_if_idx = 0; vir_if_idx < MAX_IF_NUM; vir_if_idx++) {
				dev = dst_port[vir_if_idx];
				if (dev && ether_addr_equal(eth->h_dest, dev->dev_addr) == 0) {
					skb->pkt_type = PACKET_HOST;
					break;
				}
			}
		}
	}
	return 1;
}

uint32_t keep_alive_handler(struct sk_buff *skb, struct foe_entry *entry)
{
	struct ethhdr *eth = NULL;
	u16 eth_type = ntohs(skb->protocol);
	u32 vlan1_gap = 0;
	u32 vlan2_gap = 0;
	u32 pppoe_gap = 0;
	struct vlan_hdr *vh;
	struct iphdr *iph = NULL;
	struct tcphdr *th = NULL;
	struct udphdr *uh = NULL;

/* try to recover to original SMAC/DMAC, but we don't have such information.*/
/* just use SMAC as DMAC and set Multicast address as SMAC.*/
	eth = (struct ethhdr *)(skb->data - ETH_HLEN);

	hwnat_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	hwnat_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	eth->h_source[0] = 0x1;	/* change to multicast packet, make bridge not learn this packet */
	if (eth_type == ETH_P_8021Q) {
		vlan1_gap = VLAN_HLEN;
		vh = (struct vlan_hdr *)skb->data;

		if (ntohs(vh->h_vlan_TCI) == wan_vid) {
			/* It make packet like coming from LAN port */
			vh->h_vlan_TCI = htons(lan_vid);

		} else {
			/* It make packet like coming from WAN port */
			vh->h_vlan_TCI = htons(wan_vid);
		}

		if (ntohs(vh->h_vlan_encapsulated_proto) == ETH_P_PPP_SES) {
			pppoe_gap = 8;
		} else if (ntohs(vh->h_vlan_encapsulated_proto) == ETH_P_8021Q) {
			vlan2_gap = VLAN_HLEN;
			vh = (struct vlan_hdr *)(skb->data + VLAN_HLEN);

			/* VLAN + VLAN + PPPoE */
			if (ntohs(vh->h_vlan_encapsulated_proto) == ETH_P_PPP_SES) {
				pppoe_gap = 8;
			} else {
				/* VLAN + VLAN + IP */
				eth_type = ntohs(vh->h_vlan_encapsulated_proto);
			}
		} else {
			/* VLAN + IP */
			eth_type = ntohs(vh->h_vlan_encapsulated_proto);
		}
	}

	/* Only Ipv4 NAT need KeepAlive Packet to refresh iptable */
	if (eth_type == ETH_P_IP) {
		iph = (struct iphdr *)(skb->data + vlan1_gap + vlan2_gap + pppoe_gap);
		/* Recover to original layer 4 header */
		if (iph->protocol == IPPROTO_TCP) {
			th = (struct tcphdr *)((uint8_t *)iph + iph->ihl * 4);
			foe_to_org_tcphdr(entry, iph, th);

		} else if (iph->protocol == IPPROTO_UDP) {
			uh = (struct udphdr *)((uint8_t *)iph + iph->ihl * 4);
			foe_to_org_udphdr(entry, iph, uh);
		}
		/* Recover to original layer 3 header */
		foe_to_org_iphdr(entry, iph);
		skb->pkt_type = PACKET_HOST;
	} else if (eth_type == ETH_P_IPV6) {
		skb->pkt_type = PACKET_HOST;
	} else {
		skb->pkt_type = PACKET_HOST;
	}
/* Ethernet driver will call eth_type_trans() to update skb->pkt_type.*/
/* If(destination mac != my mac)*/
/*   skb->pkt_type=PACKET_OTHERHOST;*/
/* In order to pass ip_rcv() check, we change pkt_type to PACKET_HOST here*/
/*	skb->pkt_type = PACKET_HOST;*/
	return 1;
}

uint32_t keep_alive_old_pkt_handler(struct sk_buff *skb)
{
	struct ethhdr *eth = NULL;
	u16 vir_if_idx = 0;
	struct net_device *dev;

	if ((FOE_SP(skb) == 0) || (FOE_SP(skb) == 5)) {
		vir_if_idx = remove_vlan_tag(skb);
		/* recover to right incoming interface */
		if (vir_if_idx < MAX_IF_NUM && dst_port[vir_if_idx]) {
			skb->dev = dst_port[vir_if_idx];
		} else {
			pr_info("%s unknown If (vir_if_idx=%d)\n",  __func__, vir_if_idx);
			return 1;
		}
	}

	eth = (struct ethhdr *)skb_mac_header(skb);

	if (eth->h_dest[0] & 1) {
		if (ether_addr_equal(eth->h_dest, skb->dev->broadcast) == 0)
			skb->pkt_type = PACKET_BROADCAST;
		else
			skb->pkt_type = PACKET_MULTICAST;
	} else {
		skb->pkt_type = PACKET_OTHERHOST;
		for (vir_if_idx = 0; vir_if_idx < MAX_IF_NUM; vir_if_idx++) {
			dev = dst_port[vir_if_idx];
			if (dev && ether_addr_equal(eth->h_dest, dev->dev_addr) == 0) {
				skb->pkt_type = PACKET_HOST;
				break;
			}
		}
	}
	return 0;
}

int hitbind_force_to_cpu_handler(struct sk_buff *skb, struct foe_entry *entry)
{
	u16 vir_if_idx = 0;

	if (fe_feature & HNAT_QDMA) {
		vir_if_idx = remove_vlan_tag(skb);
		if (vir_if_idx != 65535) {
			if (vir_if_idx >= FOE_4TB_SIZ) {
				pr_info("%s, entry_index error(%u)\n", __func__, vir_if_idx);
				vir_if_idx = FOE_ENTRY_NUM(skb);
				kfree_skb(skb);
				return 0;
			}
			entry = &ppe_foe_base[vir_if_idx];
		}
	}
	if (IS_IPV4_HNAT(entry) || IS_IPV4_HNAPT(entry))
		skb->dev = dst_port[entry->ipv4_hnapt.act_dp];
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV4_DSLITE(entry))
			skb->dev = dst_port[entry->ipv4_dslite.act_dp];
		else if (IS_IPV6_3T_ROUTE(entry))
			skb->dev = dst_port[entry->ipv6_3t_route.act_dp];
		else if (IS_IPV6_5T_ROUTE(entry))
			skb->dev = dst_port[entry->ipv6_5t_route.act_dp];
		else if (IS_IPV6_6RD(entry))
			skb->dev = dst_port[entry->ipv6_6rd.act_dp];
	}
	if ((!IS_IPV4_GRP(entry)) && (!(IS_IPV6_GRP(entry))))
		return 1;
	/* interface is unknown */
	if (!skb->dev) {
		if (debug_level >= 1)
			pr_info("%s, interface is unknown\n", __func__);
		kfree_skb(skb);
		return 0;
	}
	skb_set_network_header(skb, 0);
	skb_push(skb, ETH_HLEN);	/* pointer to layer2 header */
	dev_queue_xmit(skb);
	return 0;
}

int hitbind_force_mcast_to_wifi_handler(struct sk_buff *skb)
{
	int i = 0;
	struct sk_buff *skb2;

	if (fe_feature & WIFI_HNAT) {
		if (!(fe_feature & GE2_SUPPORT))
			remove_vlan_tag(skb);	/* pointer to layer3 header */
		/*if we only use GMAC1, we need to use vlan id to identify LAN/WAN port*/
		/*otherwise, CPU send untag packet to switch so we don't need to*/
		/*remove vlan tag before sending to WiFi interface*/

		skb_set_network_header(skb, 0);
		skb_push(skb, ETH_HLEN);	/* pointer to layer2 header */

		for (i = 0; i < MAX_IF_NUM; i++) {
			if ((strncmp(dst_port[i]->name, "eth", 3) != 0)) {
				skb2 = skb_clone(skb, GFP_ATOMIC);

				if (!skb2)
					return -ENOMEM;

				skb2->dev = dst_port[i];
				dev_queue_xmit(skb2);
			}
		}
	}
	kfree_skb(skb);

	return 0;
}

void get_cpu_reason_entry(int cpu_reason, struct sk_buff *skb)
{
	if (FOE_AI(skb) == cpu_reason)
		hwnat_dbg_entry = FOE_ENTRY_NUM(skb);
}

int32_t ppe_rx_handler(struct sk_buff *skb)
{
	struct foe_entry *entry = &ppe_foe_base[FOE_ENTRY_NUM(skb)];
	/*struct ethhdr *eth = (struct ethhdr *)(skb->data - ETH_HLEN);*/
	struct vlan_ethhdr *veth;

	if (debug_level >= 7) {
		hnat_cpu_reason_cnt(skb);
		if (FOE_AI(skb) == dbg_cpu_reason)
			foe_dump_pkt(skb);
	}

	if (fe_feature & HNAT_QDMA) {
		/* QDMA QoS remove CPU reason, we use special tag to identify force to CPU
		 * Notes: CPU reason & Entry ID fileds are invalid at this moment
		 */
		if (FOE_SP(skb) == 5) {
			veth = (struct vlan_ethhdr *)skb_mac_header(skb);

			if (veth->h_vlan_proto == 0x5678) {
	/*			if(fe_feature & HNAT_IPI)*/
	/*				return HnatIPIForceCPU(skb);*/

				return hitbind_force_to_cpu_handler(skb, entry);
			}
		}
	}
	/* the incoming packet is from PCI or WiFi interface */
	/* if (IS_IF_PCIE_WLAN_RX(skb)) { */
		/* return ppe_extif_rx_handler(skb); */
	if (((FOE_MAGIC_TAG(skb) == FOE_MAGIC_PCI) ||
	     (FOE_MAGIC_TAG(skb) == FOE_MAGIC_WLAN))) {
/*		if(fe_feature & HNAT_IPI)*/
/*			return HnatIPIExtIfHandler(skb);*/

		return ppe_extif_rx_handler(skb);
	} else if (FOE_AI(skb) == HIT_BIND_FORCE_TO_CPU) {
/*		if(fe_feature & HNAT_IPI)*/
/*			return HnatIPIForceCPU(skb);*/

		return hitbind_force_to_cpu_handler(skb, entry);

		/* handle the incoming packet which came back from PPE */
	} else if ((IS_IF_PCIE_WLAN_RX(skb) && ((FOE_SP(skb) == 0) || (FOE_SP(skb) == 5))) &&
		   (FOE_AI(skb) != HIT_BIND_KEEPALIVE_UC_OLD_HDR) &&
		   (FOE_AI(skb) != HIT_BIND_KEEPALIVE_MC_NEW_HDR) &&
		   (FOE_AI(skb) != HIT_BIND_KEEPALIVE_DUP_OLD_HDR)) {
		return ppe_extif_pingpong_handler(skb);
	} else if (FOE_AI(skb) == HIT_BIND_KEEPALIVE_UC_OLD_HDR) {
		if (debug_level >= 3)
			pr_info("Got HIT_BIND_KEEPALIVE_UC_OLD_HDR packet (hash index=%d)\n",
				FOE_ENTRY_NUM(skb));
		return 1;
	} else if (FOE_AI(skb) == HIT_BIND_MULTICAST_TO_CPU ||
		   FOE_AI(skb) == HIT_BIND_MULTICAST_TO_GMAC_CPU) {
		return hitbind_force_mcast_to_wifi_handler(skb);
	} else if (FOE_AI(skb) == HIT_BIND_KEEPALIVE_MC_NEW_HDR) {
		if (debug_level >= 3) {
			pr_info("Got HIT_BIND_KEEPALIVE_MC_NEW_HDR packet (hash index=%d)\n",
				FOE_ENTRY_NUM(skb));
		}
		if (keep_alive_handler(skb, entry))
			return 1;
	} else if (FOE_AI(skb) == HIT_BIND_KEEPALIVE_DUP_OLD_HDR) {
		if (debug_level >= 3)
			pr_info("RxGot HIT_BIND_KEEPALIVE_DUP_OLD_HDR packe (hash index=%d)\n",
				FOE_ENTRY_NUM(skb));
		keep_alive_old_pkt_handler(skb);
		/*change to multicast packet, make bridge not learn this packet */
		/*after kernel-2.6.36 src mac = multicast will drop by bridge,*/
		/*so we need recover correcet interface*/
		/*eth->h_source[0] = 0x1;*/

		return 1;
	}
	return 1;
}

int32_t get_pppoe_sid(struct sk_buff *skb, uint32_t vlan_gap, u16 *sid, uint16_t *ppp_tag)
{
	struct pppoe_hdr *peh = NULL;

	peh = (struct pppoe_hdr *)(skb->data + ETH_HLEN + vlan_gap);

	if (debug_level >= 6) {
		NAT_PRINT("\n==============\n");
		NAT_PRINT(" Ver=%d\n", peh->ver);
		NAT_PRINT(" Type=%d\n", peh->type);
		NAT_PRINT(" Code=%d\n", peh->code);
		NAT_PRINT(" sid=%x\n", ntohs(peh->sid));
		NAT_PRINT(" Len=%d\n", ntohs(peh->length));
		NAT_PRINT(" tag_type=%x\n", ntohs(peh->tag[0].tag_type));
		NAT_PRINT(" tag_len=%d\n", ntohs(peh->tag[0].tag_len));
		NAT_PRINT("=================\n");
	}

	*ppp_tag = peh->tag[0].tag_type;
	if (fe_feature & HNAT_IPV6) {
		if (peh->ver != 1 || peh->type != 1 ||
		    (*ppp_tag != htons(PPP_IP) &&
		    *ppp_tag != htons(PPP_IPV6))) {
			return 1;
		    }
	} else {
		if (peh->ver != 1 || peh->type != 1 || *ppp_tag != htons(PPP_IP))
			return 1;
	}

	*sid = peh->sid;
	return 0;
}

/* HNAT_V2 can push special tag */
int32_t is_special_tag(uint16_t eth_type)
{
	/* Please modify this function to speed up the packet with special tag
	 * Ex:
	 *    Ralink switch = 0x81xx
	 *    Realtek switch = 0x8899
	 */
	if ((eth_type & 0x00FF) == htons(ETH_P_8021Q)) {	/* Ralink Special Tag: 0x81xx */
		ppe_parse_result.vlan_tag = eth_type;
		return 1;
	} else {
		return 0;
	}
}

int32_t is8021Q(uint16_t eth_type)
{
	if (eth_type == htons(ETH_P_8021Q)) {
		ppe_parse_result.vlan_tag = eth_type;
		return 1;
	} else {
		return 0;
	}
}

int32_t is_hw_vlan_tx(struct sk_buff *skb)
{
	if (fe_feature & HNAT_VLAN_TX) {
		if (hwnat_vlan_tx_tag_present(skb)) {
			ppe_parse_result.vlan_tag = htons(ETH_P_8021Q);
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

int32_t ppe_parse_layer_info(struct sk_buff *skb)
{
	struct vlan_hdr *vh = NULL;
	struct ethhdr *eth = NULL;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct tcphdr *th = NULL;
	struct udphdr *uh = NULL;
	u8 ipv6_head_len = 0;
	struct vlan_hdr pseudo_vhdr;

	memset(&ppe_parse_result, 0, sizeof(ppe_parse_result));

	eth = (struct ethhdr *)skb->data;
	hwnat_memcpy(ppe_parse_result.dmac, eth->h_dest, ETH_ALEN);
	hwnat_memcpy(ppe_parse_result.smac, eth->h_source, ETH_ALEN);
	ppe_parse_result.eth_type = eth->h_proto;
	/* we cannot speed up multicase packets because both wire and wireless PCs might join same multicast group. */
	if (fe_feature & HNAT_MCAST) {
		if (is_multicast_ether_addr(&eth->h_dest[0]))
			ppe_parse_result.is_mcast = 1;
		else
			ppe_parse_result.is_mcast = 0;
	} else {
		if (is_multicast_ether_addr(&eth->h_dest[0]))
			return 1;
	}

	if (is8021Q(ppe_parse_result.eth_type) ||
	    is_special_tag(ppe_parse_result.eth_type) || is_hw_vlan_tx(skb)) {
		if (fe_feature & HNAT_VLAN_TX) {
			ppe_parse_result.vlan1_gap = 0;
			ppe_parse_result.vlan_layer++;
			pseudo_vhdr.h_vlan_TCI = htons(hwnat_vlan_tag_get(skb));
			pseudo_vhdr.h_vlan_encapsulated_proto = eth->h_proto;
			vh = (struct vlan_hdr *)&pseudo_vhdr;
		} else {
			ppe_parse_result.vlan1_gap = VLAN_HLEN;
			ppe_parse_result.vlan_layer++;
			vh = (struct vlan_hdr *)(skb->data + ETH_HLEN);
		}
		ppe_parse_result.vlan1 = vh->h_vlan_TCI;
		/* VLAN + PPPoE */
		if (ntohs(vh->h_vlan_encapsulated_proto) == ETH_P_PPP_SES) {
			ppe_parse_result.pppoe_gap = 8;
			if (get_pppoe_sid(skb, ppe_parse_result.vlan1_gap,
					  &ppe_parse_result.pppoe_sid,
					  &ppe_parse_result.ppp_tag)) {
				return 1;
			}
			ppe_parse_result.eth_type = vh->h_vlan_encapsulated_proto;
			/* Double VLAN = VLAN + VLAN */
		} else if (is8021Q(vh->h_vlan_encapsulated_proto) ||
			   is_special_tag(vh->h_vlan_encapsulated_proto)) {
			ppe_parse_result.vlan2_gap = VLAN_HLEN;
			ppe_parse_result.vlan_layer++;
			vh = (struct vlan_hdr *)(skb->data + ETH_HLEN + ppe_parse_result.vlan1_gap);
			ppe_parse_result.vlan2 = vh->h_vlan_TCI;

			/* VLAN + VLAN + PPPoE */
			if (ntohs(vh->h_vlan_encapsulated_proto) == ETH_P_PPP_SES) {
				ppe_parse_result.pppoe_gap = 8;
				if (get_pppoe_sid
				    (skb,
				     (ppe_parse_result.vlan1_gap + ppe_parse_result.vlan2_gap),
				     &ppe_parse_result.pppoe_sid, &ppe_parse_result.ppp_tag)) {
					return 1;
				}
				ppe_parse_result.eth_type = vh->h_vlan_encapsulated_proto;
			} else if (is8021Q(vh->h_vlan_encapsulated_proto)) {
				/* VLAN + VLAN + VLAN */
				ppe_parse_result.vlan_layer++;
				vh = (struct vlan_hdr *)(skb->data + ETH_HLEN +
							 ppe_parse_result.vlan1_gap + VLAN_HLEN);

				/* VLAN + VLAN + VLAN */
				if (is8021Q(vh->h_vlan_encapsulated_proto))
					ppe_parse_result.vlan_layer++;
			} else {
				/* VLAN + VLAN + IP */
				ppe_parse_result.eth_type = vh->h_vlan_encapsulated_proto;
			}
		} else {
			/* VLAN + IP */
			ppe_parse_result.eth_type = vh->h_vlan_encapsulated_proto;
		}
	} else if (ntohs(ppe_parse_result.eth_type) == ETH_P_PPP_SES) {
		/* PPPoE + IP */
		ppe_parse_result.pppoe_gap = 8;
		if (get_pppoe_sid(skb, ppe_parse_result.vlan1_gap,
				  &ppe_parse_result.pppoe_sid,
				  &ppe_parse_result.ppp_tag)) {
			return 1;
		}
	}
	/* set layer2 start addr */

	skb_set_mac_header(skb, 0);

	/* set layer3 start addr */

	skb_set_network_header(skb, ETH_HLEN + ppe_parse_result.vlan1_gap +
			       ppe_parse_result.vlan2_gap + ppe_parse_result.pppoe_gap);

	/* set layer4 start addr */
	if ((ppe_parse_result.eth_type == htons(ETH_P_IP)) ||
	    (ppe_parse_result.eth_type == htons(ETH_P_PPP_SES) &&
	    (ppe_parse_result.ppp_tag == htons(PPP_IP)))) {
		iph = (struct iphdr *)skb_network_header(skb);
		memcpy(&ppe_parse_result.iph, iph, sizeof(struct iphdr));

		if (iph->protocol == IPPROTO_TCP) {
			skb_set_transport_header(skb, ETH_HLEN + ppe_parse_result.vlan1_gap +
						 ppe_parse_result.vlan2_gap +
						 ppe_parse_result.pppoe_gap + (iph->ihl * 4));
			th = (struct tcphdr *)skb_transport_header(skb);

			memcpy(&ppe_parse_result.th, th, sizeof(struct tcphdr));
			ppe_parse_result.pkt_type = IPV4_HNAPT;
			if (iph->frag_off & htons(IP_MF | IP_OFFSET))
				return 1;
		} else if (iph->protocol == IPPROTO_UDP) {
			skb_set_transport_header(skb, ETH_HLEN + ppe_parse_result.vlan1_gap +
						 ppe_parse_result.vlan2_gap +
						 ppe_parse_result.pppoe_gap + (iph->ihl * 4));
			uh = (struct udphdr *)skb_transport_header(skb);
			memcpy(&ppe_parse_result.uh, uh, sizeof(struct udphdr));
			ppe_parse_result.pkt_type = IPV4_HNAPT;
			if (iph->frag_off & htons(IP_MF | IP_OFFSET))
				if (USE_3T_UDP_FRAG == 0)
					return 1;
		} else if (iph->protocol == IPPROTO_GRE) {
			/* do nothing */
			return 1;
		}
		if (fe_feature & HNAT_IPV6) {
			if (iph->protocol == IPPROTO_IPV6) {
				ip6h = (struct ipv6hdr *)((uint8_t *)iph + iph->ihl * 4);
				memcpy(&ppe_parse_result.ip6h, ip6h, sizeof(struct ipv6hdr));

				if (ip6h->nexthdr == NEXTHDR_TCP) {
					skb_set_transport_header(skb, ETH_HLEN + ppe_parse_result.vlan1_gap +
								 ppe_parse_result.vlan2_gap +
								 ppe_parse_result.pppoe_gap +
								 (sizeof(struct ipv6hdr)));

					th = (struct tcphdr *)skb_transport_header(skb);

					memcpy(&ppe_parse_result.th.source, &th->source, sizeof(th->source));
					memcpy(&ppe_parse_result.th.dest, &th->dest, sizeof(th->dest));
				} else if (ip6h->nexthdr == NEXTHDR_UDP) {
					skb_set_transport_header(skb, ETH_HLEN + ppe_parse_result.vlan1_gap +
								 ppe_parse_result.vlan2_gap +
								 ppe_parse_result.pppoe_gap +
								 (sizeof(struct ipv6hdr)));

					uh = (struct udphdr *)skb_transport_header(skb);
					memcpy(&ppe_parse_result.uh.source, &uh->source, sizeof(uh->source));
					memcpy(&ppe_parse_result.uh.dest, &uh->dest, sizeof(uh->dest));
				}
				ppe_parse_result.pkt_type = IPV6_6RD;
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
	} else if (ppe_parse_result.eth_type == htons(ETH_P_IPV6) ||
		   (ppe_parse_result.eth_type == htons(ETH_P_PPP_SES) &&
		    ppe_parse_result.ppp_tag == htons(PPP_IPV6))) {
		ip6h = (struct ipv6hdr *)skb_network_header(skb);
		memcpy(&ppe_parse_result.ip6h, ip6h, sizeof(struct ipv6hdr));

		if (ip6h->nexthdr == NEXTHDR_TCP) {
			skb_set_transport_header(skb, ETH_HLEN + ppe_parse_result.vlan1_gap +
						 ppe_parse_result.vlan2_gap +
						 ppe_parse_result.pppoe_gap +
						 (sizeof(struct ipv6hdr)));

			th = (struct tcphdr *)skb_transport_header(skb);
			memcpy(&ppe_parse_result.th, th, sizeof(struct tcphdr));
			ppe_parse_result.pkt_type = IPV6_5T_ROUTE;
		} else if (ip6h->nexthdr == NEXTHDR_UDP) {
			skb_set_transport_header(skb, ETH_HLEN + ppe_parse_result.vlan1_gap +
						 ppe_parse_result.vlan2_gap +
						 ppe_parse_result.pppoe_gap +
						 (sizeof(struct ipv6hdr)));
			uh = (struct udphdr *)skb_transport_header(skb);
			memcpy(&ppe_parse_result.uh, uh, sizeof(struct udphdr));
			ppe_parse_result.pkt_type = IPV6_5T_ROUTE;
		} else if (ip6h->nexthdr == NEXTHDR_IPIP) {
			ipv6_head_len = sizeof(struct iphdr);
			memcpy(&ppe_parse_result.iph, ip6h + ipv6_head_len,
			       sizeof(struct iphdr));
			ppe_parse_result.pkt_type = IPV4_DSLITE;
		} else {
			ppe_parse_result.pkt_type = IPV6_3T_ROUTE;
		}

	} else {
		return 1;
	}

	if (debug_level >= 6) {
		pr_info("--------------\n");
		pr_info("DMAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
			ppe_parse_result.dmac[0], ppe_parse_result.dmac[1],
			 ppe_parse_result.dmac[2], ppe_parse_result.dmac[3],
			 ppe_parse_result.dmac[4], ppe_parse_result.dmac[5]);
		pr_info("SMAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
			ppe_parse_result.smac[0], ppe_parse_result.smac[1],
			 ppe_parse_result.smac[2], ppe_parse_result.smac[3],
			 ppe_parse_result.smac[4], ppe_parse_result.smac[5]);
		pr_info("Eth_Type=%x\n", ppe_parse_result.eth_type);
		if (ppe_parse_result.vlan1_gap > 0)
			pr_info("VLAN1 ID=%x\n", ntohs(ppe_parse_result.vlan1));

		if (ppe_parse_result.vlan2_gap > 0)
			pr_info("VLAN2 ID=%x\n", ntohs(ppe_parse_result.vlan2));

		if (ppe_parse_result.pppoe_gap > 0) {
			pr_info("PPPOE Session ID=%x\n", ppe_parse_result.pppoe_sid);
			pr_info("PPP Tag=%x\n", ntohs(ppe_parse_result.ppp_tag));
		}
		pr_info("PKT_TYPE=%s\n",
			ppe_parse_result.pkt_type ==
			 0 ? "IPV4_HNAT" : ppe_parse_result.pkt_type ==
			 1 ? "IPV4_HNAPT" : ppe_parse_result.pkt_type ==
			 3 ? "IPV4_DSLITE" : ppe_parse_result.pkt_type ==
			 5 ? "IPV6_ROUTE" : ppe_parse_result.pkt_type == 7 ? "IPV6_6RD" : "Unknown");
		if (ppe_parse_result.pkt_type == IPV4_HNAT) {
			pr_info("SIP=%s\n", ip_to_str(ntohl(ppe_parse_result.iph.saddr)));
			pr_info("DIP=%s\n", ip_to_str(ntohl(ppe_parse_result.iph.daddr)));
			pr_info("TOS=%x\n", ntohs(ppe_parse_result.iph.tos));
		} else if (ppe_parse_result.pkt_type == IPV4_HNAPT) {
			pr_info("SIP=%s\n", ip_to_str(ntohl(ppe_parse_result.iph.saddr)));
			pr_info("DIP=%s\n", ip_to_str(ntohl(ppe_parse_result.iph.daddr)));
			pr_info("TOS=%x\n", ntohs(ppe_parse_result.iph.tos));

			if (ppe_parse_result.iph.protocol == IPPROTO_TCP) {
				pr_info("TCP SPORT=%d\n", ntohs(ppe_parse_result.th.source));
				pr_info("TCP DPORT=%d\n", ntohs(ppe_parse_result.th.dest));
			} else if (ppe_parse_result.iph.protocol == IPPROTO_UDP) {
				pr_info("UDP SPORT=%d\n", ntohs(ppe_parse_result.uh.source));
				pr_info("UDP DPORT=%d\n", ntohs(ppe_parse_result.uh.dest));
			}
		} else if (ppe_parse_result.pkt_type == IPV6_5T_ROUTE) {
			pr_info("ING SIPv6->DIPv6: %08X:%08X:%08X:%08X:%d-> %08X:%08X:%08X:%08X:%d\n",
				ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[0]),
			     ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[1]),
			     ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[2]),
			     ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[3]),
			     ntohs(ppe_parse_result.th.source),
			     ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[0]),
			     ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[1]),
			     ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[2]),
			     ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[3]),
			     ntohs(ppe_parse_result.th.dest));
		} else if (ppe_parse_result.pkt_type == IPV6_6RD) {
			/* fill in ipv4 6rd entry */
			pr_info("packet_type = IPV6_6RD\n");
			pr_info("SIP=%s\n", ip_to_str(ntohl(ppe_parse_result.iph.saddr)));
			pr_info("DIP=%s\n", ip_to_str(ntohl(ppe_parse_result.iph.daddr)));

			pr_info("Checksum=%x\n", ntohs(ppe_parse_result.iph.check));
			pr_info("ipV4 ID =%x\n", ntohs(ppe_parse_result.iph.id));
			pr_info("Flag=%x\n", ntohs(ppe_parse_result.iph.frag_off) >> 13);
			pr_info("TTL=%x\n", ppe_parse_result.iph.ttl);
			pr_info("TOS=%x\n", ppe_parse_result.iph.tos);
		}
	}

	return 0;
}

int32_t ppe_fill_L2_info(struct sk_buff *skb, struct foe_entry *entry)
{
	/* if this entry is already in binding state, skip it */
	if (entry->bfib1.state == BIND)
		return 1;

	/* Set VLAN Info - VLAN1/VLAN2 */
	/* Set Layer2 Info - DMAC, SMAC */
	if ((ppe_parse_result.pkt_type == IPV4_HNAT) || (ppe_parse_result.pkt_type == IPV4_HNAPT)) {
		if (entry->ipv4_hnapt.bfib1.pkt_type == IPV4_DSLITE) {	/* DS-Lite WAN->LAN */
			if (fe_feature & HNAT_IPV6) {
				foe_set_mac_hi_info(entry->ipv4_dslite.dmac_hi, ppe_parse_result.dmac);
				foe_set_mac_lo_info(entry->ipv4_dslite.dmac_lo, ppe_parse_result.dmac);
				foe_set_mac_hi_info(entry->ipv4_dslite.smac_hi, ppe_parse_result.smac);
				foe_set_mac_lo_info(entry->ipv4_dslite.smac_lo, ppe_parse_result.smac);
				entry->ipv4_dslite.vlan1 = ntohs(ppe_parse_result.vlan1);
				entry->ipv4_dslite.pppoe_id = ntohs(ppe_parse_result.pppoe_sid);
				entry->ipv4_dslite.vlan2_winfo = ntohs(ppe_parse_result.vlan2);

				entry->ipv4_dslite.etype = ntohs(ppe_parse_result.vlan_tag);
			} else {
				return 1;
			}

		} else {	/* IPv4 WAN<->LAN */
			foe_set_mac_hi_info(entry->ipv4_hnapt.dmac_hi, ppe_parse_result.dmac);
			foe_set_mac_lo_info(entry->ipv4_hnapt.dmac_lo, ppe_parse_result.dmac);
			foe_set_mac_hi_info(entry->ipv4_hnapt.smac_hi, ppe_parse_result.smac);
			foe_set_mac_lo_info(entry->ipv4_hnapt.smac_lo, ppe_parse_result.smac);
			entry->ipv4_hnapt.vlan1 = ntohs(ppe_parse_result.vlan1);
#ifdef VPRI_REMARK_TEST
			/* VPRI=0x7 */
			entry->ipv4_hnapt.vlan1 |= (7 << 13);
#endif
			entry->ipv4_hnapt.pppoe_id = ntohs(ppe_parse_result.pppoe_sid);
			entry->ipv4_hnapt.vlan2_winfo = ntohs(ppe_parse_result.vlan2);

			entry->ipv4_hnapt.etype = ntohs(ppe_parse_result.vlan_tag);
		}
	} else {
		if (fe_feature & HNAT_IPV6) {
			foe_set_mac_hi_info(entry->ipv6_5t_route.dmac_hi, ppe_parse_result.dmac);
			foe_set_mac_lo_info(entry->ipv6_5t_route.dmac_lo, ppe_parse_result.dmac);
			foe_set_mac_hi_info(entry->ipv6_5t_route.smac_hi, ppe_parse_result.smac);
			foe_set_mac_lo_info(entry->ipv6_5t_route.smac_lo, ppe_parse_result.smac);
			entry->ipv6_5t_route.vlan1 = ntohs(ppe_parse_result.vlan1);
			entry->ipv6_5t_route.pppoe_id = ntohs(ppe_parse_result.pppoe_sid);
			entry->ipv6_5t_route.vlan2_winfo = ntohs(ppe_parse_result.vlan2);

			entry->ipv6_5t_route.etype = ntohs(ppe_parse_result.vlan_tag);
		} else {
				return 1;
		}
	}

/* VLAN Layer:*/
/* 0: outgoing packet is untagged packet*/
/* 1: outgoing packet is tagged packet*/
/* 2: outgoing packet is double tagged packet*/
/* 3: outgoing packet is triple tagged packet*/
/* 4: outgoing packet is fourfold tagged packet*/
	entry->bfib1.vlan_layer = ppe_parse_result.vlan_layer;

#ifdef VLAN_LAYER_TEST
	/* outgoing packet is triple tagged packet */
	entry->bfib1.vlan_layer = 3;
	entry->ipv4_hnapt.vlan1 = 2;
	entry->ipv4_hnapt.vlan2 = 1;
#endif
	if (ppe_parse_result.pppoe_gap)
		entry->bfib1.psn = 1;
	else
		entry->bfib1.psn = 0;

	entry->ipv4_hnapt.bfib1.vpm = 1;	/* 0x8100 */
	return 0;
}

static uint16_t ppe_get_chkbase(struct iphdr *iph)
{
	u16 org_chksum = ntohs(iph->check);
	u16 org_tot_len = ntohs(iph->tot_len);
	u16 org_id = ntohs(iph->id);
	u16 chksum_tmp, tot_len_tmp, id_tmp;
	u32 tmp = 0;
	u16 chksum_base = 0;

	chksum_tmp = ~(org_chksum);
	tot_len_tmp = ~(org_tot_len);
	id_tmp = ~(org_id);
	tmp = chksum_tmp + tot_len_tmp + id_tmp;
	tmp = ((tmp >> 16) & 0x7) + (tmp & 0xFFFF);
	tmp = ((tmp >> 16) & 0x7) + (tmp & 0xFFFF);
	chksum_base = tmp & 0xFFFF;

	return chksum_base;
}

int32_t ppe_fill_L3_info(struct sk_buff *skb, struct foe_entry *entry)
{
	/* IPv4 or IPv4 over PPPoE */
	if ((ppe_parse_result.eth_type == htons(ETH_P_IP)) ||
	    (ppe_parse_result.eth_type == htons(ETH_P_PPP_SES) &&
	     ppe_parse_result.ppp_tag == htons(PPP_IP))) {
		if ((ppe_parse_result.pkt_type == IPV4_HNAT) ||
		    (ppe_parse_result.pkt_type == IPV4_HNAPT)) {
			if (entry->ipv4_hnapt.bfib1.pkt_type == IPV4_DSLITE) {	/* DS-Lite WAN->LAN */
				if (fe_feature & HNAT_IPV6) {
					if (fe_feature & PPE_MIB)
						entry->ipv4_dslite.iblk2.mibf = 1;

						entry->ipv4_dslite.bfib1.rmt = 1;	/* remove outer IPv6 header */
						entry->ipv4_dslite.iblk2.dscp = ppe_parse_result.iph.tos;
				}

			} else {
				entry->ipv4_hnapt.new_sip = ntohl(ppe_parse_result.iph.saddr);
				entry->ipv4_hnapt.new_dip = ntohl(ppe_parse_result.iph.daddr);
				entry->ipv4_hnapt.iblk2.dscp = ppe_parse_result.iph.tos;
#ifdef DSCP_REMARK_TEST
				entry->ipv4_hnapt.iblk2.dscp = 0xff;
#endif
				if (fe_feature & PPE_MIB)
					entry->ipv4_hnapt.iblk2.mibf = 1;
			}
		}
		if (fe_feature & HNAT_IPV6) {
			if (ppe_parse_result.pkt_type == IPV6_6RD) {
				/* fill in ipv4 6rd entry */
				entry->ipv6_6rd.tunnel_sipv4 = ntohl(ppe_parse_result.iph.saddr);
				entry->ipv6_6rd.tunnel_dipv4 = ntohl(ppe_parse_result.iph.daddr);
				entry->ipv6_6rd.hdr_chksum = ppe_get_chkbase(&ppe_parse_result.iph);
				entry->ipv6_6rd.flag = (ntohs(ppe_parse_result.iph.frag_off) >> 13);
				entry->ipv6_6rd.ttl = ppe_parse_result.iph.ttl;
				entry->ipv6_6rd.dscp = ppe_parse_result.iph.tos;
				if (fe_feature & PPE_MIB)
					entry->ipv6_6rd.iblk2.mibf = 1;

				if ((hnat_chip_name & MT7623_HWNAT) ||
				    (hnat_chip_name & MT7622_HWNAT) ||
				    (hnat_chip_name & LEOPARD_HWNAT)) {
					hwnat_set_6rd_id(entry);
				}
				/* IPv4 DS-Lite and IPv6 6RD shall be turn on by SW during initialization */
				entry->bfib1.pkt_type = IPV6_6RD;
			}
		}
	}
	if (fe_feature & HNAT_IPV6) {
		/* IPv6 or IPv6 over PPPoE */
		if (ppe_parse_result.eth_type == htons(ETH_P_IPV6) ||
		    (ppe_parse_result.eth_type == htons(ETH_P_PPP_SES) &&
			  ppe_parse_result.ppp_tag == htons(PPP_IPV6))) {
			if (ppe_parse_result.pkt_type == IPV6_3T_ROUTE ||
			    ppe_parse_result.pkt_type == IPV6_5T_ROUTE) {
				/* incoming packet is 6RD and need to remove outer IPv4 header */
				if (entry->bfib1.pkt_type == IPV6_6RD) {
					entry->ipv6_3t_route.bfib1.rmt = 1;
					entry->ipv6_3t_route.iblk2.dscp =
					    (ppe_parse_result.ip6h.
					     priority << 4 | (ppe_parse_result.ip6h.flow_lbl[0] >> 4));
					if (fe_feature & PPE_MIB)
						entry->ipv6_3t_route.iblk2.mibf = 1;

				} else {
					/* fill in ipv6 routing entry */
					entry->ipv6_3t_route.ipv6_sip0 =
					    ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[0]);
					entry->ipv6_3t_route.ipv6_sip1 =
					    ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[1]);
					entry->ipv6_3t_route.ipv6_sip2 =
					    ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[2]);
					entry->ipv6_3t_route.ipv6_sip3 =
					    ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[3]);

					entry->ipv6_3t_route.ipv6_dip0 =
					    ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[0]);
					entry->ipv6_3t_route.ipv6_dip1 =
					    ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[1]);
					entry->ipv6_3t_route.ipv6_dip2 =
					    ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[2]);
					entry->ipv6_3t_route.ipv6_dip3 =
					    ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[3]);
					entry->ipv6_3t_route.iblk2.dscp =
					    (ppe_parse_result.ip6h.
					     priority << 4 | (ppe_parse_result.ip6h.flow_lbl[0] >> 4));

	/*#ifdef DSCP_REMARK_TEST*/
	/*				entry->ipv6_3t_route.iblk2.dscp = 0xff;*/
	/*#endif*/

					if (fe_feature & PPE_MIB)
						entry->ipv6_3t_route.iblk2.mibf = 1;
				}
			} else if (ppe_parse_result.pkt_type == IPV4_DSLITE) {
				/* fill in DSLite entry */
				entry->ipv4_dslite.tunnel_sipv6_0 =
				    ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[0]);
				entry->ipv4_dslite.tunnel_sipv6_1 =
				    ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[1]);
				entry->ipv4_dslite.tunnel_sipv6_2 =
				    ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[2]);
				entry->ipv4_dslite.tunnel_sipv6_3 =
				    ntohl(ppe_parse_result.ip6h.saddr.s6_addr32[3]);

				entry->ipv4_dslite.tunnel_dipv6_0 =
				    ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[0]);
				entry->ipv4_dslite.tunnel_dipv6_1 =
				    ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[1]);
				entry->ipv4_dslite.tunnel_dipv6_2 =
				    ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[2]);
				entry->ipv4_dslite.tunnel_dipv6_3 =
				    ntohl(ppe_parse_result.ip6h.daddr.s6_addr32[3]);
				if (fe_feature & PPE_MIB)
					entry->ipv4_dslite.iblk2.mibf = 1;

				memcpy(entry->ipv4_dslite.flow_lbl, ppe_parse_result.ip6h.flow_lbl,
				       sizeof(ppe_parse_result.ip6h.flow_lbl));
				entry->ipv4_dslite.priority = ppe_parse_result.ip6h.priority;
				entry->ipv4_dslite.hop_limit = ppe_parse_result.ip6h.hop_limit;
				/* IPv4 DS-Lite and IPv6 6RD shall be turn on by SW during initialization */
				entry->bfib1.pkt_type = IPV4_DSLITE;
			};
		}
	} else {
		if ((!IS_IPV4_GRP(entry)) && (!(IS_IPV6_GRP(entry))))
			NAT_PRINT("unknown Pkt_type=%d\n", entry->bfib1.pkt_type);
		return 1;
	}

	return 0;
}

int32_t ppe_fill_L4_info(struct sk_buff *skb, struct foe_entry *entry)
{
	if (ppe_parse_result.pkt_type == IPV4_HNAPT) {
		/* DS-LIte WAN->LAN */
		if (entry->ipv4_hnapt.bfib1.pkt_type == IPV4_DSLITE)
			return 0;
		/* Set Layer4 Info - NEW_SPORT, NEW_DPORT */
		if (ppe_parse_result.iph.protocol == IPPROTO_TCP) {
			entry->ipv4_hnapt.new_sport = ntohs(ppe_parse_result.th.source);
			entry->ipv4_hnapt.new_dport = ntohs(ppe_parse_result.th.dest);
			entry->ipv4_hnapt.bfib1.udp = TCP;
		} else if (ppe_parse_result.iph.protocol == IPPROTO_UDP) {
			entry->ipv4_hnapt.new_sport = ntohs(ppe_parse_result.uh.source);
			entry->ipv4_hnapt.new_dport = ntohs(ppe_parse_result.uh.dest);
			entry->ipv4_hnapt.bfib1.udp = UDP;
		}
	}

	/*else if (ppe_parse_result.pkt_type == IPV4_HNAT)*/
		/* do nothing */
	/*else if (ppe_parse_result.pkt_type == IPV6_1T_ROUTE)*/
		/* do nothing */
	/*else if (ppe_parse_result.pkt_type == IPV6_3T_ROUTE)*/
		/* do nothing */
	/*else if (ppe_parse_result.pkt_type == IPV6_5T_ROUTE)*/
		/* do nothing */
	return 0;
}

static void ppe_set_infoblk2(struct _info_blk2 *iblk2, uint32_t fpidx, uint32_t port_mg,
			     uint32_t port_ag)
{
/* Replace 802.1Q priority by user priority */

/*#ifdef FORCE_UP_TEST*/
/*	u32 reg;*/
/**/
/*	iblk2->fp = 1;*/
/*	iblk2->up = 7;*/
/*	reg = reg_read(RALINK_ETH_SW_BASE + 0x2704);*/
/*	reg |= (0x1 << 11);*/
/*	reg_write(RALINK_ETH_SW_BASE + 0x2704, reg);*/
/*#endif*/

	/* we need to lookup another multicast table if this is multicast flow */
	if (ppe_parse_result.is_mcast) {
		iblk2->mcast = 1;
		if (fe_feature & WIFI_HNAT) {
			if (fpidx == 3)
				fpidx = 0;	/* multicast flow not go to WDMA */
		}
	} else {
		iblk2->mcast = 0;
	}
/* 0:PSE,1:GSW, 2:GMAC,4:PPE,5:QDMA,7=DROP */
	    iblk2->dp = fpidx;

	if (!(fe_feature & HNAT_QDMA))
		iblk2->fqos = 0;	/* PDMA MODE should not goes to QoS */
	iblk2->acnt = port_ag;

	if (hnat_chip_name & MT7621_HWNAT) {
		/*mt7621 share the same struct,*/
		/* so related parameter need seed set 1*/
		iblk2->qid1 = 0x3;
		iblk2->noused = 0x3;
		iblk2->wdmaid = 1;
		iblk2->winfo = 1;
	}
}

/*for 16 queue test*/
unsigned char queue_number;

void set_ppe_qid(struct sk_buff *skb, struct foe_entry *entry)
{
	unsigned int qidx;

	if (IS_IPV4_GRP(entry)) {
		if (skb->mark > 63)
			skb->mark = 0;
	qidx = M2Q_table[skb->mark];
		if (hnat_chip_name & MT7622_HWNAT)
			entry->ipv4_hnapt.iblk2.qid1 = ((qidx & 0x30) >> 4);

		entry->ipv4_hnapt.iblk2.qid = (qidx & 0x0f);
	}
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV6_GRP(entry)) {
			if (skb->mark > 63)
				skb->mark = 0;
			qidx = M2Q_table[skb->mark];
			if (hnat_chip_name & MT7622_HWNAT)
				entry->ipv6_3t_route.iblk2.qid1 = ((qidx & 0x30) >> 4);

			entry->ipv6_3t_route.iblk2.qid = (qidx & 0x0f);
		}
	}
}

void set_warp_wifi_dp(struct sk_buff *skb, struct foe_entry *entry)
{
	if (IS_IPV4_GRP(entry)) {
		entry->ipv4_hnapt.iblk2.fqos = 0;/* MT7622 wifi hw_nat not support QoS */
		ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 3, 0x3F, 0x3F);	/* 3=WDMA */
		entry->ipv4_hnapt.iblk2.wdmaid = (FOE_WDMA_ID(skb) & 0x01);
		entry->ipv4_hnapt.iblk2.winfo = 1;
		entry->ipv4_hnapt.vlan2_winfo =
			((FOE_RX_ID(skb) & 0x03) << 14) | ((FOE_WC_ID(skb) & 0xff) << 6) |
			(FOE_BSS_ID(skb) & 0x3f);
	}
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV6_GRP(entry)) {
			ppe_set_infoblk2(&entry->ipv6_3t_route.iblk2, 3, 0x3F, 0x3F);/* 3=WDMA */
			entry->ipv6_3t_route.iblk2.fqos = 0;	/* MT7622 wifi hw_nat not support qos */
			entry->ipv6_3t_route.iblk2.wdmaid = (FOE_WDMA_ID(skb) & 0x01);
			entry->ipv6_3t_route.iblk2.winfo = 1;
			entry->ipv6_3t_route.vlan2_winfo =
				((FOE_RX_ID(skb) & 0x03) << 14) | ((FOE_WC_ID(skb) & 0xff) << 6) |
				(FOE_BSS_ID(skb) & 0x3f);
		}
	}
}

void pp_fill_qdma_entry(struct sk_buff *skb, struct foe_entry *entry)
{
	if (IS_IPV4_GRP(entry)) {
		entry->ipv4_hnapt.bfib1.vpm = 0;	/* etype remark */
		if (ppe_parse_result.vlan1 == 0) {
			entry->ipv4_hnapt.vlan1 = FOE_ENTRY_NUM(skb);
			entry->ipv4_hnapt.etype = ntohs(0x5678);
			entry->bfib1.vlan_layer = 1;
		} else if (ppe_parse_result.vlan2 == 0) {
			entry->ipv4_hnapt.vlan1 = FOE_ENTRY_NUM(skb);
			entry->ipv4_hnapt.etype = ntohs(0x5678);
			entry->ipv4_hnapt.vlan2_winfo = ntohs(ppe_parse_result.vlan1);
			entry->bfib1.vlan_layer = 2;
		} else {
			entry->ipv4_hnapt.vlan1 = FOE_ENTRY_NUM(skb);
			entry->ipv4_hnapt.etype = ntohs(0x5678);
			entry->ipv4_hnapt.vlan2_winfo = ntohs(ppe_parse_result.vlan1);
			entry->bfib1.vlan_layer = 3;
		}
		if (FOE_SP(skb) == 5)/* wifi to wifi not go to pse port6 */
			entry->ipv4_hnapt.iblk2.fqos = 0;
		else {
			if (fe_feature & WAN_TO_WLAN_QOS)
				entry->ipv4_hnapt.iblk2.fqos = 1;
			else
				entry->ipv4_hnapt.iblk2.fqos = 0;
		}
	}
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV6_GRP(entry)) {
			if (ppe_parse_result.vlan1 == 0) {
				entry->ipv6_3t_route.vlan1 = FOE_ENTRY_NUM(skb);
				entry->ipv6_3t_route.etype = ntohs(0x5678);
				entry->bfib1.vlan_layer = 1;
			} else if (ppe_parse_result.vlan2 == 0) {
				entry->ipv6_3t_route.vlan1 = FOE_ENTRY_NUM(skb);
				entry->ipv6_3t_route.etype = ntohs(0x5678);
				entry->ipv6_3t_route.vlan2_winfo = ntohs(ppe_parse_result.vlan1);
				entry->bfib1.vlan_layer = 2;
			} else {
				entry->ipv6_3t_route.vlan1 = FOE_ENTRY_NUM(skb);
				entry->ipv6_3t_route.etype = ntohs(0x5678);
				entry->ipv6_3t_route.vlan2_winfo = ntohs(ppe_parse_result.vlan1);
				entry->bfib1.vlan_layer = 3;
			}
			if (FOE_SP(skb) == 5) {
				entry->ipv6_3t_route.iblk2.fqos = 0;	/* wifi to wifi not go to pse port6 */
			} else {
				if (fe_feature & WAN_TO_WLAN_QOS)
					entry->ipv6_3t_route.iblk2.fqos = 1;
				else
					entry->ipv6_3t_route.iblk2.fqos = 0;
			}
		}
	}
}

/*port means pse port*/
void set_dst_port(struct foe_entry *entry, int port, int group)
{
	if (IS_IPV4_GRP(entry))
		ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, port, 0x3F, group);	/* 0=PDMA */

	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV6_GRP(entry))
			ppe_set_infoblk2(&entry->ipv6_3t_route.iblk2, port, 0x3F, group);
	}
}

void set_wifi_dp(struct sk_buff *skb, struct foe_entry *entry, int gmac_no, int pse_port)
{
	/*handle to wlan info*/
	if (fe_feature & HNAT_QDMA) {
		if (fe_feature & WARP_WHNAT) {
			if (gmac_no == 3) {
				set_warp_wifi_dp(skb, entry);
			} else {
				pp_fill_qdma_entry(skb, entry);
				set_dst_port(entry, pse_port, 0x3f);
			}
		} else {
			pp_fill_qdma_entry(skb, entry);
			set_dst_port(entry, pse_port, 0x3f);
		}
	}
}

/*wan at p4 ==>wan_p4 =1 */
/*sp_tag enable ==> sp_tag = 1*/
int eth_sptag_lan_port_ipv4(struct foe_entry *entry, int wan_p4)
{
	if (wan_p4 == 1) {
		if (((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 1) ||
		    ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 2) ||
		    ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 3) ||
		    ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 4)) {
			if ((bind_dir == DOWNSTREAM_ONLY) || (bind_dir == BIDIRECTION))
				ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 1, 0x3F, 1);
			else
				return 1;
		}
	} else {
		if (((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 2) ||
		    ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 3) ||
		    ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 4) ||
		    ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 5)) {
			if ((bind_dir == DOWNSTREAM_ONLY) || (bind_dir == BIDIRECTION))
				ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 1, 0x3F, 1);
			else
				return 1;
		}
	}
	return 0;
}

int eth_sptag_wan_port_ipv4(struct foe_entry *entry, int wan_p4)
{
	if (wan_p4 == 1) {
		if ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 5) {
			if ((bind_dir == UPSTREAM_ONLY) || (bind_dir == BIDIRECTION))
				ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 1, 0x3F, 2);

			else
				return 1;
		}
	} else {
		if ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 1) {
			if ((bind_dir == UPSTREAM_ONLY) || (bind_dir == BIDIRECTION))
				ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 1, 0x3F, 2);

			else
				return 1;
		}
	}
	return 0;
}

int eth_sptag_lan_port_ipv6(struct foe_entry *entry, int wan_p4)
{
	if (wan_p4 == 1) {
		if (((entry->ipv6_5t_route.vlan1 & VLAN_VID_MASK) == 1) ||
		    ((entry->ipv6_5t_route.vlan1 & VLAN_VID_MASK) == 2) ||
		    ((entry->ipv6_5t_route.vlan1 & VLAN_VID_MASK) == 3) ||
		    ((entry->ipv6_5t_route.vlan1 & VLAN_VID_MASK) == 4)) {
			if ((bind_dir == DOWNSTREAM_ONLY) || (bind_dir == BIDIRECTION))
				ppe_set_infoblk2(&entry->ipv6_5t_route.iblk2, 1, 0x3F, 1);
			else
				return 1;
		}
	} else {
		if (((entry->ipv6_5t_route.vlan1 & VLAN_VID_MASK) == 2) ||
		    ((entry->ipv6_5t_route.vlan1 & VLAN_VID_MASK) == 3) ||
		    ((entry->ipv6_5t_route.vlan1 & VLAN_VID_MASK) == 4) ||
		    ((entry->ipv6_5t_route.vlan1 & VLAN_VID_MASK) == 5)) {
			if ((bind_dir == DOWNSTREAM_ONLY) || (bind_dir == BIDIRECTION))
				ppe_set_infoblk2(&entry->ipv6_5t_route.iblk2, 1, 0x3F, 1);
			else
				return 1;
		}
	}
	return 0;
}

int eth_sptag_wan_port_ipv6(struct foe_entry *entry, int wan_p4)
{
	if (wan_p4 == 1) {
		if ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 5) {
			if ((bind_dir == UPSTREAM_ONLY) || (bind_dir == BIDIRECTION))
				ppe_set_infoblk2(&entry->ipv6_5t_route.iblk2, 1, 0x3F, 2);
			else
				return 1;
		}
	} else {
		if ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == 1) {
			if ((bind_dir == UPSTREAM_ONLY) || (bind_dir == BIDIRECTION))
				ppe_set_infoblk2(&entry->ipv6_5t_route.iblk2, 1, 0x3F, 2);

			else
				return 1;
		}
	}
	return 0;
}

int set_eth_dp_gmac1(struct foe_entry *entry, int gmac_no)
{
				/* only one GMAC */
	if (IS_IPV4_GRP(entry)) {
		if (fe_feature & HNAT_SP_TAG) {
			if (fe_feature & HNAT_WAN_P4) {
				eth_sptag_lan_port_ipv4(entry, 1); /* sp tag enable, wan at port4 */
				eth_sptag_wan_port_ipv4(entry, 1);
			} else {
				eth_sptag_lan_port_ipv4(entry, 0);
				eth_sptag_wan_port_ipv4(entry, 0);
			} /* not support one arm */
		} else {
			if ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == lan_vid) {
				if ((bind_dir == DOWNSTREAM_ONLY) || (bind_dir == BIDIRECTION))
					ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 1, 0x3F, 1);
				else
					return 1;
			} else if ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == wan_vid) {
				if ((bind_dir == UPSTREAM_ONLY) || (bind_dir == BIDIRECTION))
					ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 1, 0x3F, 2);

				else
					return 1;
			} else {/* one-arm */
				ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 1, 0x3F, 1);
			}
		}
	}
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV6_GRP(entry)) {
			if (fe_feature & HNAT_SP_TAG) {
				if (fe_feature & HNAT_WAN_P4) {
					eth_sptag_lan_port_ipv4(entry, 1); /* sp tag enable, wan at port4 */
					eth_sptag_wan_port_ipv4(entry, 1);
				} else {
					eth_sptag_lan_port_ipv4(entry, 0);
					eth_sptag_wan_port_ipv4(entry, 0);
				}
			} else {
				if ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == lan_vid) {
					if ((bind_dir == DOWNSTREAM_ONLY) || (bind_dir == BIDIRECTION))
						ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 1, 0x3F, 1);
					else
						return 1;
				} else if ((entry->ipv4_hnapt.vlan1 & VLAN_VID_MASK) == wan_vid) {
					if ((bind_dir == UPSTREAM_ONLY) || (bind_dir == BIDIRECTION))
						ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 1, 0x3F, 2);

					else
						return 1;
				} else/* one-arm */
					ppe_set_infoblk2(&entry->ipv4_hnapt.iblk2, 1, 0x3F, 1);
			}
		}
	}
	return 0;
}

int set_eth_dp_gmac2(struct foe_entry *entry, int gmac_no)
{
		/* RT3883/MT7621 with 2xGMAC - Assuming GMAC2=WAN  and GMAC1=LAN */
	if (gmac_no == 1) {
		if ((bind_dir == DOWNSTREAM_ONLY) || (bind_dir == BIDIRECTION))
			set_dst_port(entry, 1, 1); /*pse port1,goup1*/

		else
			return 1;
	} else if (gmac_no == 2) {
		if ((bind_dir == UPSTREAM_ONLY) || (bind_dir == BIDIRECTION))
			set_dst_port(entry, 2, 2); /*pse port1, group2*/
		else
			return 1;
	}
	return 0;
}

void set_eth_fqos(struct sk_buff *skb, struct foe_entry *entry)
{
	if (IS_IPV4_GRP(entry)) {
		if (((FOE_MAGIC_TAG(skb) == FOE_MAGIC_PCI) ||
		     (FOE_MAGIC_TAG(skb) == FOE_MAGIC_WLAN))) {
			if (fe_feature & ETH_QOS)
				entry->ipv4_hnapt.iblk2.fqos = 1;
			else
				entry->ipv4_hnapt.iblk2.fqos = 0;
		} else {
			if (FOE_SP(skb) == 5) {
				entry->ipv4_hnapt.iblk2.fqos = 0;
			} else {
				if (fe_feature & ETH_QOS)
					entry->ipv4_hnapt.iblk2.fqos = 1;
				else
					entry->ipv4_hnapt.iblk2.fqos = 0;
			}
		}
	}
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV6_GRP(entry)) {
			if (((FOE_MAGIC_TAG(skb) == FOE_MAGIC_PCI) ||
			     (FOE_MAGIC_TAG(skb) == FOE_MAGIC_WLAN))) {
				if (fe_feature & ETH_QOS)
					entry->ipv6_5t_route.iblk2.fqos = 1;
				else
					entry->ipv6_5t_route.iblk2.fqos = 0;

			} else {
				if (FOE_SP(skb) == 5) {
					entry->ipv6_5t_route.iblk2.fqos = 0;
				} else{
					if (fe_feature & ETH_QOS)
						entry->ipv6_5t_route.iblk2.fqos = 1;
					else
						entry->ipv6_5t_route.iblk2.fqos = 0;
				}
			}
		}
	}
}

int32_t setforce_port_qdmatx_pdmarx(struct sk_buff *skb, struct foe_entry *entry, int gmac_no)
{
	int ret;

	set_ppe_qid(skb, entry);
	if ((strncmp(skb->dev->name, "eth", 3) != 0)) {
		if (fe_feature & WIFI_HNAT)
			set_wifi_dp(skb, entry, gmac_no, 0);
		else
			return 1;
	} else {
		set_eth_fqos(skb, entry);
		if (fe_feature & GE2_SUPPORT)
			ret = set_eth_dp_gmac2(entry, gmac_no);
		else
			ret = set_eth_dp_gmac1(entry, gmac_no);
	}
	return ret;
}

int32_t setforce_port_pdmatx_pdmarx(struct sk_buff *skb, struct foe_entry *entry, int gmac_no)
{
	int ret;

	if ((strncmp(skb->dev->name, "eth", 3) != 0)) {
		if (fe_feature & WIFI_HNAT)
			set_wifi_dp(skb, entry, gmac_no, 0);
		else
			return 1;
	} else {
		if (fe_feature & GE2_SUPPORT)
			ret = set_eth_dp_gmac2(entry, gmac_no);
		else
			ret = set_eth_dp_gmac1(entry, gmac_no);
	}
	return ret;
}

int32_t setforce_port_qdmatx_qdmarx(struct sk_buff *skb, struct foe_entry *entry, int gmac_no)
{
	int ret;

	set_ppe_qid(skb, entry);
	if ((strncmp(skb->dev->name, "eth", 3) != 0)) {
		if (fe_feature & WIFI_HNAT)
			set_wifi_dp(skb, entry, gmac_no, 5);
		else
			return 1;
	} else {
		set_eth_fqos(skb, entry);
		if (fe_feature & GE2_SUPPORT)
			ret = set_eth_dp_gmac2(entry, gmac_no);
		else
			ret = set_eth_dp_gmac1(entry, gmac_no);
	}
	return ret;
}

uint32_t ppe_set_ext_if_num(struct sk_buff *skb, struct foe_entry *entry)
{
	u32 offset = 0;

	if (fe_feature & WIFI_HNAT) {
		u32 i = 0;
		int dev_match = 0;

		for (i = 0; i < MAX_IF_NUM; i++) {
			if (dst_port[i] == skb->dev) {
				offset = i;
				dev_match = 1;
				if (debug_level >= 1)
					pr_info("dev match offset, name=%s ifined=%x\n", skb->dev->name, i);
				break;
			}
		}
		if (dev_match == 0) {
			if (debug_level >= 1)
				pr_info("%s UnKnown Interface, offset =%x\n", __func__, i);
			return 1;
		}

		if (IS_IPV4_HNAT(entry) || IS_IPV4_HNAPT(entry)) {
			entry->ipv4_hnapt.act_dp = offset;
			return 0;
		}
		if (fe_feature & HNAT_IPV6) {
			if (IS_IPV4_DSLITE(entry))
				entry->ipv4_dslite.act_dp = offset;
			else if (IS_IPV6_3T_ROUTE(entry))
				entry->ipv6_3t_route.act_dp = offset;
			else if (IS_IPV6_5T_ROUTE(entry))
				entry->ipv6_5t_route.act_dp = offset;
			else if (IS_IPV6_6RD(entry))
				entry->ipv6_6rd.act_dp = offset;
			else
				return 1;
		}
	}
	return 0;
}

void ppe_set_entry_bind(struct sk_buff *skb, struct foe_entry *entry)
{
	u32 current_time;
	/* Set Current time to time_stamp field in information block 1 */
	current_time = reg_read(FOE_TS) & 0xFFFF;
	entry->bfib1.time_stamp = (uint16_t)current_time;

	/* Ipv4: TTL / Ipv6: Hot Limit filed */
	entry->ipv4_hnapt.bfib1.ttl = DFL_FOE_TTL_REGEN;
	/* enable cache by default */
	entry->ipv4_hnapt.bfib1.cah = 1;

	hwnat_set_packet_sampling(entry);

	if (fe_feature & PRE_BIND) {
		entry->udib1.preb = 1;
	} else {
		/* Change Foe Entry State to Binding State */
		entry->bfib1.state = BIND;
		/* Dump Binding Entry */
		if (debug_level >= 1)
			foe_dump_entry(FOE_ENTRY_NUM(skb));
	}
}

void ppe_dev_reg_handler(struct net_device *dev)
{
	int i;

	for (i = 0; i < MAX_IF_NUM; i++) {
		if (dst_port[i] == dev) {
			pr_info("%s : %s dst_port table has beed registered(%d)\n", __func__, dev->name, i);
			return;
		}
		if (!dst_port[i]) {
			dst_port[i] = dev;
			break;
		}
	}
	pr_info("%s : ineterface %s register (%d)\n", __func__, dev->name, i);
}

void ppe_dev_unreg_handler(struct net_device *dev)
{
	int i;

	for (i = 0; i < MAX_IF_NUM; i++) {
		if (dst_port[i] == dev) {
			dst_port[i] = NULL;
			break;
		}
	}
	pr_info("%s : ineterface %s set null (%d)\n", __func__, dev->name, i);
}

int get_done_bit(struct sk_buff *skb, struct foe_entry *entry)
{
	int done_bit;

	if (IS_IPV4_HNAT(entry) || IS_IPV4_HNAPT(entry)) {
		done_bit = entry->ipv4_hnapt.resv1;
		return done_bit;
	}
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV4_DSLITE(entry)) {
			done_bit = entry->ipv4_dslite.resv1;
		} else if (IS_IPV6_3T_ROUTE(entry)) {
			done_bit = entry->ipv6_3t_route.resv1;
		} else if (IS_IPV6_5T_ROUTE(entry)) {
			done_bit = entry->ipv6_5t_route.resv1;
		} else if (IS_IPV6_6RD(entry)) {
			done_bit = entry->ipv6_6rd.resv1;
		} else {
			pr_info("get packet format something wrong\n");
			return 0;
		}
	}

	if ((done_bit != 0) && (done_bit != 1)) {
		pr_info("done bit something wrong, done_bit = %d\n", done_bit);
		done_bit = 0;
	}
	/* pr_info("index = %d, done_bit=%d\n", FOE_ENTRY_NUM(skb), done_bit); */
	return done_bit;
}

void set_ppe_table_done(struct foe_entry *entry)
{
	if (IS_IPV4_HNAT(entry) || IS_IPV4_HNAPT(entry)) {
		entry->ipv4_hnapt.resv1 = 1;
		return;
	}
	if (fe_feature & HNAT_IPV6) {
		if (IS_IPV4_DSLITE(entry))
			entry->ipv4_dslite.resv1 = 1;
		else if (IS_IPV6_3T_ROUTE(entry))
			entry->ipv6_3t_route.resv1 = 1;
		else if (IS_IPV6_5T_ROUTE(entry))
			entry->ipv6_5t_route.resv1 = 1;
		else if (IS_IPV6_6RD(entry))
			entry->ipv6_6rd.resv1 = 1;
		else
			pr_info("set packet format something wrong\n");
	}
}

int get_skb_interface(struct sk_buff *skb)
{
	if ((strncmp(skb->dev->name, "rai", 3) == 0) ||
	    (strncmp(skb->dev->name, "apclii", 6) == 0) ||
	    (strncmp(skb->dev->name, "wdsi", 4) == 0) ||
	    (strncmp(skb->dev->name, "wlan", 4) == 0))
		return 1;
	else
		return 0;
}

int32_t ppe_tx_handler(struct sk_buff *skb, int gmac_no)
{
	struct foe_entry *entry;
	struct ps_entry *ps_entry;

	u8 which_region;
	int count = 100000;

	which_region = tx_decide_which_region(skb);
	if (which_region == ALL_INFO_ERROR) {
		if (pr_debug_ratelimited())
			pr_info("ppe_tx_handler : ALL_INFO_ERROR\n");
		return 1;
	}

	entry = &ppe_foe_base[FOE_ENTRY_NUM(skb)];

	if (fe_feature & PACKET_SAMPLING)
		ps_entry = &ppe_ps_base[FOE_ENTRY_NUM(skb)];

	if (FOE_ENTRY_NUM(skb) == 0x3fff)
		return 1;
		/* pr_info("FOE_ENTRY_NUM(skb)=%x\n", FOE_ENTRY_NUM(skb)); */

	if (FOE_ENTRY_NUM(skb) >= FOE_4TB_SIZ)
		return 1;
		/* pr_info("FOE_ENTRY_NUM(skb)=%x\n", FOE_ENTRY_NUM(skb)); */

	 /* Packet is interested by ALG?*/
	 /* Yes: Don't enter binind state*/
	 /* No: If flow rate exceed binding threshold, enter binding state.*/

	if (IS_MAGIC_TAG_PROTECT_VALID(skb) &&
	    (FOE_AI(skb) == HIT_UNBIND_RATE_REACH) &&
	    (FOE_ALG(skb) == 0)) {
		if (fe_feature & SEMI_AUTO_MODE) {
			if (get_done_bit(skb, entry) != 0)
				return 1;
		}

		if (fe_feature & WLAN_OPTIMIZE) {
			if (bridge_lan_subnet(skb)) {
				if (!get_skb_interface(skb))
					USE_3T_UDP_FRAG = 0;
				else
					USE_3T_UDP_FRAG = 1;
				if (USE_3T_UDP_FRAG == 0)
					return 1;
			} else {
				USE_3T_UDP_FRAG = 0;
			}
		} else {
			if (fe_feature & UDP_FRAG) {
				if (bridge_lan_subnet(skb))
					USE_3T_UDP_FRAG = 1;
				else
					USE_3T_UDP_FRAG = 0;
			}
		}
		if (debug_level >= 6)
			pr_info(" which_region = %d\n", which_region);

		/* get start addr for each layer */
		if (ppe_parse_layer_info(skb)) {
			memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
			return 1;
		}
		/* Set Layer2 Info */
		if (ppe_fill_L2_info(skb, entry)) {
			memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
			return 1;
		}
		/* Set Layer3 Info */
		if (ppe_fill_L3_info(skb, entry)) {
			memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
			return 1;
		}

		/* Set Layer4 Info */
		if (ppe_fill_L4_info(skb, entry)) {
			memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
			return 1;
		}

		/* Set force port info */
		if (fe_feature & QDMA_TX_RX) {
			if (setforce_port_qdmatx_qdmarx(skb, entry, gmac_no)) {
				memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
				return 1;
			}
		} else if (fe_feature & HNAT_QDMA) {
			if (setforce_port_qdmatx_pdmarx(skb, entry, gmac_no)) {
				memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
				return 1;
			}
		} else {
			if (setforce_port_pdmatx_pdmarx(skb, entry, gmac_no)) {
				memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
				return 1;
			}
		}

		/* Set Pseudo Interface info in Foe entry */
		if (ppe_set_ext_if_num(skb, entry)) {
			memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
			return 1;
		}
		if ((fe_feature & HNAT_QDMA) && (fe_feature & HNAT_MCAST)) {
			if (ppe_parse_result.is_mcast) {
				foe_mcast_entry_qid(ppe_parse_result.vlan1,
						    ppe_parse_result.dmac,
						    M2Q_table[skb->mark]);
			}
		}
		if (fe_feature & PPE_MIB) {
		/*clear mib counter*/
			reg_write(MIB_SER_CR, FOE_ENTRY_NUM(skb) | (1 << 16));
			do {
				if (!((reg_read(MIB_SER_CR) & 0x10000) >> 16))
				break;
				/* usleep_range(100, 110); */
			} while (--count);
			reg_read(MIB_SER_R0);
			reg_read(MIB_SER_R1);
			reg_read(MIB_SER_R1);
			reg_read(MIB_SER_R2);
		}

		if (fe_feature & AUTO_MODE)
			ppe_set_entry_bind(skb, entry); /* Enter binding state */
		if (fe_feature & SEMI_AUTO_MODE) {
			set_ppe_table_done(entry);
			/*make sure data write to dram*/
			wmb();
		}
		if (fe_feature & PACKET_SAMPLING) {
		/*add sampling policy here*/
			ps_entry->en = 0x1 << 1;
			ps_entry->pkt_cnt = 0x10;
		}

	} else if (IS_MAGIC_TAG_PROTECT_VALID(skb) &&
		  (FOE_AI(skb) == HIT_BIND_PACKET_SAMPLING)) {
		/* this is duplicate packet in PS function*/
		/* just drop it */
		pr_info("PS drop#%d\n", FOE_ENTRY_NUM(skb));
		memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
		return 0;
	} else if (IS_MAGIC_TAG_PROTECT_VALID(skb) &&
		  (FOE_AI(skb) == HIT_BIND_KEEPALIVE_MC_NEW_HDR ||
		  (FOE_AI(skb) == HIT_BIND_KEEPALIVE_DUP_OLD_HDR))) {
			/*this is duplicate packet in keepalive new header mode*/
			/*just drop it */
		if (debug_level >= 3)
			pr_info("TxGot HITBIND_KEEPALIVE_DUP_OLD packe (%d)\n",
				FOE_ENTRY_NUM(skb));
		memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
		return 0;
	} else if (IS_MAGIC_TAG_PROTECT_VALID(skb) &&
		  (FOE_AI(skb) == HIT_UNBIND_RATE_REACH) &&
		  (FOE_ALG(skb) == 1)) {
		if (debug_level >= 3)
			NAT_PRINT("FOE_ALG=1 (Entry=%d)\n", FOE_ENTRY_NUM(skb));
	}
	if (fe_feature & PRE_BIND) {
		if (FOE_AI(skb) == HIT_PRE_BIND) {
/*#ifdef PREBIND_TEST*/
/*		if (jiffies % 2 == 0) {*/
/*			pr_info("drop prebind packet jiffies=%lu\n", jiffies);*/
/*			memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);*/
/*			return 0;*/
/*		}*/
/*#endif*/

			if (entry->udib1.preb && entry->bfib1.state != BIND) {
				entry->bfib1.state = BIND;
				entry->udib1.preb = 0;
				/* Dump Binding Entry */
				if (debug_level >= 1)
					foe_dump_entry(FOE_ENTRY_NUM(skb));
			} else {
				/* drop duplicate prebind notify packet */
				memset(FOE_INFO_START_ADDR(skb), 0, FOE_INFO_LEN);
				return 0;
			}
		}
	}
	return 1;
}

void ppe_setfoe_ebl(uint32_t foe_ebl)
{
	u32 ppe_flow_set = 0;

	ppe_flow_set = reg_read(PPE_FLOW_SET);

	/* FOE engine need to handle unicast/multicast/broadcast flow */
	if (foe_ebl == 1) {
		ppe_flow_set |= (BIT_IPV4_NAPT_EN | BIT_IPV4_NAT_EN);
		ppe_flow_set |= (BIT_IPV4_NAT_FRAG_EN | BIT_UDP_IP4F_NAT_EN);	/* ip fragment */
		ppe_flow_set |= (BIT_IPV4_HASH_GREK);
		if (fe_feature & HNAT_IPV6) {
			ppe_flow_set |=
			    (BIT_IPV4_DSL_EN | BIT_IPV6_6RD_EN | BIT_IPV6_3T_ROUTE_EN |
			     BIT_IPV6_5T_ROUTE_EN);
			/* ppe_flow_set |= (BIT_IPV6_HASH_FLAB); // flow label */
			ppe_flow_set |= (BIT_IPV6_HASH_GREK);
		}

	} else {
		ppe_flow_set &= ~(BIT_IPV4_NAPT_EN | BIT_IPV4_NAT_EN);
		ppe_flow_set &= ~(BIT_IPV4_NAT_FRAG_EN);
		if (fe_feature & HNAT_IPV6) {
			ppe_flow_set &=
			    ~(BIT_IPV4_DSL_EN | BIT_IPV6_6RD_EN | BIT_IPV6_3T_ROUTE_EN |
			      BIT_IPV6_5T_ROUTE_EN);
			/* ppe_flow_set &= ~(BIT_IPV6_HASH_FLAB); */
			ppe_flow_set &= ~(BIT_IPV6_HASH_GREK);
		} else {
			ppe_flow_set &= ~(BIT_FUC_FOE | BIT_FMC_FOE | BIT_FBC_FOE);
		}
	}

	reg_write(PPE_FLOW_SET, ppe_flow_set);
}

static int ppe_setfoe_hash_mode(u32 hash_mode, struct device *dev)
{
	/* Allocate FOE table base */
	if (!foe_alloc_tbl(FOE_4TB_SIZ, dev))
		return 0;

	switch (FOE_4TB_SIZ) {
	case 1024:
		reg_modify_bits(PPE_FOE_CFG, FOE_TBL_SIZE_1K, 0, 3);
		break;
	case 2048:
		reg_modify_bits(PPE_FOE_CFG, FOE_TBL_SIZE_2K, 0, 3);
		break;
	case 4096:
		reg_modify_bits(PPE_FOE_CFG, FOE_TBL_SIZE_4K, 0, 3);
		break;
	case 8192:
		reg_modify_bits(PPE_FOE_CFG, FOE_TBL_SIZE_8K, 0, 3);
		break;
	case 16384:
		reg_modify_bits(PPE_FOE_CFG, FOE_TBL_SIZE_16K, 0, 3);
		break;
	case 32768:
		reg_modify_bits(PPE_FOE_CFG, FOE_TBL_SIZE_32K, 0, 3);
		break;
	}

	/* Set Hash Mode */
	reg_modify_bits(PPE_FOE_CFG, hash_mode, 14, 2);
	reg_write(PPE_HASH_SEED, HASH_SEED);

	if (fe_feature & DBG_IPV6_SIP)
		reg_modify_bits(PPE_FOE_CFG, 3, 18, 2);	/* ipv6_sip */
	else if (fe_feature & DBG_IPV4_SIP)
		reg_modify_bits(PPE_FOE_CFG, 2, 18, 2);	/* ipv4_sip */
	else if (fe_feature & DBG_SP)
		reg_modify_bits(PPE_FOE_CFG, 1, 18, 2);	/* sport */
	else
		reg_modify_bits(PPE_FOE_CFG, 0, 18, 2);	/* disable */

	if (fe_feature & HNAT_IPV6)
		reg_modify_bits(PPE_FOE_CFG, 1, 3, 1);	/* entry size = 80bytes */
	else
		reg_modify_bits(PPE_FOE_CFG, 0, 3, 1);	/* entry size = 64bytes */

	if (fe_feature & PRE_BIND)
		reg_modify_bits(PPE_FOE_CFG, 1, 6, 1);	/* pre-bind age enable */

	/* Set action for FOE search miss */
	reg_modify_bits(PPE_FOE_CFG, FWD_CPU_BUILD_ENTRY, 4, 2);

	return 1;
}

static void ppe_setage_out(void)
{
	/* set Bind Non-TCP/UDP Age Enable */
	reg_modify_bits(PPE_FOE_CFG, DFL_FOE_NTU_AGE, 7, 1);

	/* set Unbind State Age Enable */
	reg_modify_bits(PPE_FOE_CFG, DFL_FOE_UNB_AGE, 8, 1);

	/* set min threshold of packet count for aging out at unbind state */
	reg_modify_bits(PPE_FOE_UNB_AGE, DFL_FOE_UNB_MNP, 16, 16);

	/* set Delta time for aging out an unbind FOE entry */
	reg_modify_bits(PPE_FOE_UNB_AGE, DFL_FOE_UNB_DLTA, 0, 8);

	if (!(fe_feature & MANUAL_MODE)) {
		/* set Bind TCP Age Enable */
		reg_modify_bits(PPE_FOE_CFG, DFL_FOE_TCP_AGE, 9, 1);

		/* set Bind UDP Age Enable */
		reg_modify_bits(PPE_FOE_CFG, DFL_FOE_UDP_AGE, 10, 1);

		/* set Bind TCP FIN Age Enable */
		reg_modify_bits(PPE_FOE_CFG, DFL_FOE_FIN_AGE, 11, 1);

		/* set Delta time for aging out an bind UDP FOE entry */
		reg_modify_bits(PPE_FOE_BND_AGE0, DFL_FOE_UDP_DLTA, 0, 16);

		/* set Delta time for aging out an bind Non-TCP/UDP FOE entry */
		reg_modify_bits(PPE_FOE_BND_AGE0, DFL_FOE_NTU_DLTA, 16, 16);

		/* set Delta time for aging out an bind TCP FIN FOE entry */
		reg_modify_bits(PPE_FOE_BND_AGE1, DFL_FOE_FIN_DLTA, 16, 16);

		/* set Delta time for aging out an bind TCP FOE entry */
		reg_modify_bits(PPE_FOE_BND_AGE1, DFL_FOE_TCP_DLTA, 0, 16);
	} else {
		/* fix TCP last ACK issue */
		/* Only need to enable Bind TCP FIN aging out function */
		reg_modify_bits(PPE_FOE_CFG, DFL_FOE_FIN_AGE, 11, 1);
		/* set Delta time for aging out an bind TCP FIN FOE entry */
		reg_modify_bits(PPE_FOE_BND_AGE1, DFL_FOE_FIN_DLTA, 16, 16);
	}
}

static void ppe_setfoe_ka(void)
{
	/* set Keep alive packet with new/org header */
	reg_modify_bits(PPE_FOE_CFG, DFL_FOE_KA, 12, 2);

	/* Keep alive timer value */
	reg_modify_bits(PPE_FOE_KA, DFL_FOE_KA_T, 0, 16);

	/* Keep alive time for bind FOE TCP entry */
	reg_modify_bits(PPE_FOE_KA, DFL_FOE_TCP_KA, 16, 8);

	/* Keep alive timer for bind FOE UDP entry */
	reg_modify_bits(PPE_FOE_KA, DFL_FOE_UDP_KA, 24, 8);

	/* Keep alive timer for bind Non-TCP/UDP entry */
	reg_modify_bits(PPE_BIND_LMT_1, DFL_FOE_NTU_KA, 16, 8);

	if (fe_feature & PRE_BIND)
		reg_modify_bits(PPE_BIND_LMT_1, DFL_PBND_RD_LMT, 24, 8);
}

static void ppe_setfoe_bind_rate(uint32_t foe_bind_rate)
{
	/* Allowed max entries to be build during a time stamp unit */

	/* smaller than 1/4 of total entries */
	reg_modify_bits(PPE_FOE_LMT1, DFL_FOE_QURT_LMT, 0, 14);

	/* between 1/2 and 1/4 of total entries */
	reg_modify_bits(PPE_FOE_LMT1, DFL_FOE_HALF_LMT, 16, 14);

	/* between full and 1/2 of total entries */
	reg_modify_bits(PPE_FOE_LMT2, DFL_FOE_FULL_LMT, 0, 14);

	/* Set reach bind rate for unbind state */
	reg_modify_bits(PPE_FOE_BNDR, foe_bind_rate, 0, 16);
	if (fe_feature & PRE_BIND)
		reg_modify_bits(PPE_FOE_BNDR, DFL_PBND_RD_PRD, 16, 16);
}

static void ppe_setfoe_glocfg_ebl(uint32_t ebl)
{
	if (ebl == 1) {
		/* PPE Engine Enable */
		reg_modify_bits(PPE_GLO_CFG, 1, 0, 1);

	if (fe_feature & HNAT_IPV6) {
		/* TSID Enable */
		pr_info("TSID Enable\n");
		reg_modify_bits(PPE_GLO_CFG, 1, 1, 1);
	}

	if (fe_feature & HNAT_MCAST) {
		/* Enable multicast table lookup */
		reg_modify_bits(PPE_GLO_CFG, 1, 7, 1);
		reg_modify_bits(PPE_GLO_CFG, 0, 12, 2);	/* Decide by PPE entry hash index */
		reg_modify_bits(PPE_MCAST_PPSE, 0, 0, 4);	/* multicast port0 map to PDMA */
		reg_modify_bits(PPE_MCAST_PPSE, 1, 4, 4);	/* multicast port1 map to GMAC1 */
		reg_modify_bits(PPE_MCAST_PPSE, 2, 8, 4);	/* multicast port2 map to GMAC2 */
		reg_modify_bits(PPE_MCAST_PPSE, 5, 12, 4);	/* multicast port3 map to QDMA */
	}			/* CONFIG_PPE_MCAST // */

		if (fe_feature & QDMA_TX_RX)
			reg_write(PPE_DFT_CPORT, 0x55555555);	/* default CPU port is port5 (QDMA) */
		else
			reg_write(PPE_DFT_CPORT, 0);	/* default CPU port is port0 (PDMA) */

	if (fe_feature & HNAT_IPV6)
		reg_modify_bits(PPE_DFT_CPORT, 1, 31, 1);

	if (fe_feature & PACKET_SAMPLING)
		reg_write(PS_CFG, 0x3);	/* Enable PacketSampling, Disable Aging */
	/* reg_write(PS_CFG, 1); //Enable PacketSampling */
		if (fe_feature & PPE_MIB) {
			reg_write(MIB_CFG, 0x03);	/* Enable MIB & read clear */
			reg_write(MIB_CAH_CTRL, 0x01);	/* enable mib cache */
		}

		/* PPE Packet with TTL=0 alert to cpu*/
		reg_modify_bits(PPE_GLO_CFG, DFL_TTL0_DRP, 4, 1);

	} else {
		/* PPE Engine Disable */
		reg_modify_bits(PPE_GLO_CFG, 0, 0, 1);
		if (fe_feature & PACKET_SAMPLING)
			reg_write(PS_CFG, 0);	/* Disable PacketSampling */
		if (fe_feature & PPE_MIB)
			reg_write(MIB_CFG, 0x00);	/* Disable MIB */
	}
}

#if (0)
static void foe_free_tbl(uint32_t num_of_entry)
{
	u32 foe_tbl_size;

	foe_tbl_size = num_of_entry * sizeof(struct foe_entry);
	dma_free_coherent(NULL, foe_tbl_size, ppe_foe_base, ppe_phy_foe_base);
	reg_write(PPE_FOE_BASE, 0);
}
#endif

static int32_t ppe_eng_start(void)
{
	/* Set PPE Flow Set */
	ppe_setfoe_ebl(1);

	/* Set Auto Age-Out Function */
	ppe_setage_out();

	/* Set PPE FOE KEEPALIVE TIMER */
	ppe_setfoe_ka();

	/* Set PPE FOE Bind Rate */
	ppe_setfoe_bind_rate(DFL_FOE_BNDR);

	/* Set PPE Global Configuration */
	ppe_setfoe_glocfg_ebl(1);
	return 0;
}

#if (0)
static int32_t ppe_eng_stop(void)
{
	/* Set PPE FOE ENABLE */
	ppe_setfoe_glocfg_ebl(0);

	/* Set PPE Flow Set */
	ppe_setfoe_ebl(0);

	/* Free FOE table */
	foe_free_tbl(FOE_4TB_SIZ);

	return 0;
}
#endif

struct net_device *ra_dev_get_by_name(const char *name)
{
	return dev_get_by_name(&init_net, name);
}

void eth_register(void)
{
	struct net_device *dev;
	int i;

	dev = ra_dev_get_by_name(DEV_NAME_HNAT_LAN);
	ppe_dev_reg_handler(dev);
	for (i = 0; i < MAX_IF_NUM; i++) {
		if (dst_port[i] == dev) {
			pr_info("%s :dst_port[%d] =%s\n", __func__, i, dev->name);
			DP_GMAC1 = i;
			break;
		}
	}
	if (fe_feature & GE2_SUPPORT) {
		dev = ra_dev_get_by_name(DEV_NAME_HNAT_WAN);
		ppe_dev_reg_handler(dev);
		for (i = 0; i < MAX_IF_NUM; i++) {
			if (dst_port[i] == dev) {
				pr_info("%s :dst_port[%d] =%s\n", __func__, i, dev->name);
				DP_GMAC2 = i;
				break;
			}
		}
	}
}

static void ppe_set_dst_port(uint32_t ebl)
{
	int j;

	if (ebl) {
		if (fe_feature & WIFI_HNAT)
			eth_register();

	} else { /* disable */
		if (fe_feature & WIFI_HNAT) {
			dev_put(dst_port[DP_GMAC1]);
			dev_put(dst_port[DP_GMAC2]);
			for (j = 0; j < MAX_IF_NUM; j++) {
				if (dst_port[j])
					dst_port[j] = NULL;
			}
		}
	}
}

uint32_t set_gdma_fwd(uint32_t ebl)
{
	u32 data = 0;

	data = reg_read(FE_GDMA1_FWD_CFG);

	if (ebl) {
		data &= ~0x7777;
		/* Uni-cast frames forward to PPE */
		data |= GDM1_UFRC_P_PPE;
		/* Broad-cast MAC address frames forward to PPE */
		data |= GDM1_BFRC_P_PPE;
		/* Multi-cast MAC address frames forward to PPE */
		data |= GDM1_MFRC_P_PPE;
		/* Other MAC address frames forward to PPE */
		data |= GDM1_OFRC_P_PPE;

	} else {
		data &= ~0x7777;
		/* Uni-cast frames forward to CPU */
		data |= GDM1_UFRC_P_CPU;
		/* Broad-cast MAC address frames forward to CPU */
		data |= GDM1_BFRC_P_CPU;
		/* Multi-cast MAC address frames forward to CPU */
		data |= GDM1_MFRC_P_CPU;
		/* Other MAC address frames forward to CPU */
		data |= GDM1_OFRC_P_CPU;
	}

	reg_write(FE_GDMA1_FWD_CFG, data);

	if (fe_feature & GE2_SUPPORT) {
		data = reg_read(FE_GDMA2_FWD_CFG);

		if (ebl) {
			data &= ~0x7777;
			/* Uni-cast frames forward to PPE */
			data |= GDM1_UFRC_P_PPE;
			/* Broad-cast MAC address frames forward to PPE */
			data |= GDM1_BFRC_P_PPE;
			/* Multi-cast MAC address frames forward to PPE */
			data |= GDM1_MFRC_P_PPE;
			/* Other MAC address frames forward to PPE */
			data |= GDM1_OFRC_P_PPE;

		} else {
			data &= ~0x7777;
			/* Uni-cast frames forward to CPU */
			data |= GDM1_UFRC_P_CPU;
			/* Broad-cast MAC address frames forward to CPU */
			data |= GDM1_BFRC_P_CPU;
			/* Multi-cast MAC address frames forward to CPU */
			data |= GDM1_MFRC_P_CPU;
			/* Other MAC address frames forward to CPU */
			data |= GDM1_OFRC_P_CPU;
		}
		reg_write(FE_GDMA2_FWD_CFG, data);
	}

	return 0;
}

void ppe_set_cache_ebl(void)
{
	/* clear cache table before enabling cache */
	reg_modify_bits(CAH_CTRL, 1, 9, 1);
	reg_modify_bits(CAH_CTRL, 0, 9, 1);

	/* Cache enable */
	reg_modify_bits(CAH_CTRL, 1, 0, 1);
}

static void ppe_set_ip_prot(void)
{
	/* IP Protocol Field for IPv4 NAT or IPv6 3-tuple flow */
	/* Don't forget to turn on related bits in PPE_IP_PROT_CHK register if you want to support
	 * another IP protocol.
	 */
	/* FIXME: enable it to support IP fragement */
	reg_write(PPE_IP_PROT_CHK, 0xFFFFFFFF);	/* IPV4_NXTH_CHK and IPV6_NXTH_CHK */
	/* reg_modify_bits(PPE_IP_PROT_0, IPPROTO_GRE, 0, 8); */
	/* reg_modify_bits(PPE_IP_PROT_0, IPPROTO_TCP, 8, 8); */
	/* reg_modify_bits(PPE_IP_PROT_0, IPPROTO_UDP, 16, 8); */
	/* reg_modify_bits(PPE_IP_PROT_0, IPPROTO_IPV6, 24, 8); */
}

DEFINE_TIMER(update_foe_ac_timer, update_foe_ac_timer_handler, 0, 0);

void update_foe_ac_timer_handler(unsigned long unused)
{
	ac_info[1].ag_byte_cnt += reg_read(AC_BASE + 1 * 16);	/* 64bit bytes cnt */
	ac_info[1].ag_byte_cnt += ((unsigned long long)(reg_read(AC_BASE + 1 * 16 + 4)) << 32);	/* 64bit bytes cnt */
	ac_info[1].ag_pkt_cnt += reg_read(AC_BASE + 1 * 16 + 8);	/* 32bites packet cnt */
	ac_info[2].ag_byte_cnt += reg_read(AC_BASE + 2 * 16);	/* 64bit bytes cnt */
	ac_info[2].ag_byte_cnt += ((unsigned long long)(reg_read(AC_BASE + 2 * 16 + 4)) << 32);	/* 64bit bytes cnt */
	ac_info[2].ag_pkt_cnt += reg_read(AC_BASE + 2 * 16 + 8);	/* 32bites packet cnt */
	update_foe_ac_timer.expires = jiffies + 16 * HZ;
	add_timer(&update_foe_ac_timer);
}

void update_foe_ac_init(void)
{
	ac_info[1].ag_byte_cnt = 0;
	ac_info[1].ag_pkt_cnt = 0;
	ac_info[2].ag_byte_cnt = 0;
	ac_info[2].ag_pkt_cnt = 0;
	ac_info[3].ag_byte_cnt = 0;
	ac_info[3].ag_pkt_cnt = 0;
	ac_info[4].ag_byte_cnt = 0;
	ac_info[4].ag_pkt_cnt = 0;
	ac_info[5].ag_byte_cnt = 0;
	ac_info[5].ag_pkt_cnt = 0;
	ac_info[6].ag_byte_cnt = 0;
	ac_info[6].ag_pkt_cnt = 0;
}

void foe_ac_update_ebl(int ebl)
{
	if (fe_feature & ACCNT_MAINTAINER) {
		if (ebl) {
			update_foe_ac_init();
			update_foe_ac_timer.expires = jiffies + HZ;
			add_timer(&update_foe_ac_timer);
		} else {
			if (timer_pending(&update_foe_ac_timer))
				del_timer_sync(&update_foe_ac_timer);
		}
	}
}

void foe_clear_entry(struct neighbour *neigh)
{
	int hash_index, clear;
	struct foe_entry *entry;
	u32 *daddr = (u32 *)neigh->primary_key;
	const u8 *addrtmp;
	u8 mac0, mac1, mac2, mac3, mac4, mac5;
	u32 dip;

	dip = (u32)(*daddr);
	clear = 0;
	addrtmp = neigh->ha;
	mac0 = (u8)(*addrtmp);
	mac1 = (u8)(*(addrtmp + 1));
	mac2 = (u8)(*(addrtmp + 2));
	mac3 = (u8)(*(addrtmp + 3));
	mac4 = (u8)(*(addrtmp + 4));
	mac5 = (u8)(*(addrtmp + 5));

	for (hash_index = 0; hash_index < FOE_4TB_SIZ; hash_index++) {
		entry = &ppe_foe_base[hash_index];
		if (entry->bfib1.state == BIND) {
			/*pr_info("before old mac= %x:%x:%x:%x:%x:%x, new_dip=%x\n",*/
			/*	entry->ipv4_hnapt.dmac_hi[3],*/
			/*	entry->ipv4_hnapt.dmac_hi[2],*/
			/*	entry->ipv4_hnapt.dmac_hi[1],*/
			/*	entry->ipv4_hnapt.dmac_hi[0],*/
			/*	entry->ipv4_hnapt.dmac_lo[1],*/
			/*	entry->ipv4_hnapt.dmac_lo[0], entry->ipv4_hnapt.new_dip);*/
			if (entry->ipv4_hnapt.new_dip == ntohl(dip)) {
				if ((entry->ipv4_hnapt.dmac_hi[3] != mac0) ||
				    (entry->ipv4_hnapt.dmac_hi[2] != mac1) ||
				    (entry->ipv4_hnapt.dmac_hi[1] != mac2) ||
				    (entry->ipv4_hnapt.dmac_hi[0] != mac3) ||
				    (entry->ipv4_hnapt.dmac_lo[1] != mac4) ||
				    (entry->ipv4_hnapt.dmac_lo[0] != mac5)) {
					pr_info("%s: state=%d\n", __func__, neigh->nud_state);
					reg_modify_bits(PPE_FOE_CFG, ONLY_FWD_CPU, 4, 2);

					entry->ipv4_hnapt.udib1.state = INVALID;
					entry->ipv4_hnapt.udib1.time_stamp = reg_read(FOE_TS) & 0xFF;
					ppe_set_cache_ebl();
					mod_timer(&hwnat_clear_entry_timer, jiffies + 3 * HZ);

					pr_info("delete old entry: dip =%x\n", ntohl(dip));

					pr_info("old mac= %x:%x:%x:%x:%x:%x, dip=%x\n",
						entry->ipv4_hnapt.dmac_hi[3],
						entry->ipv4_hnapt.dmac_hi[2],
						entry->ipv4_hnapt.dmac_hi[1],
						entry->ipv4_hnapt.dmac_hi[0],
						entry->ipv4_hnapt.dmac_lo[1],
						entry->ipv4_hnapt.dmac_lo[0],
						ntohl(dip));
					pr_info("new mac= %x:%x:%x:%x:%x:%x, dip=%x\n",
						mac0, mac1, mac2, mac3, mac4, mac5, ntohl(dip));
				}
			}
		}
	}
}

static int wh2_netevent_handler(struct notifier_block *unused,
				unsigned long event, void *ptr)
{
	struct net_device *dev = NULL;
	struct neighbour *neigh = NULL;

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		neigh = ptr;
		dev = neigh->dev;
		if (dev)
			foe_clear_entry(neigh);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block hnat_netevent_nb __read_mostly = {
	.notifier_call = wh2_netevent_handler,
};

void hwnat_config_setting(void)
{
	hnat_chip_name |= MT7621_HWNAT;
	hnat_chip_name |= MT7622_HWNAT;
	hnat_chip_name |= MT7623_HWNAT;
	hnat_chip_name |= LEOPARD_HWNAT;
}

void fe_feature_setting(void)
{
	fe_feature |= GE2_SUPPORT;
	fe_feature |= HNAT_IPV6;
	fe_feature |= HNAT_VLAN_TX;
	fe_feature |= HNAT_MCAST;
	fe_feature |= HNAT_QDMA;
	fe_feature |= WARP_WHNAT;
	fe_feature |= WIFI_HNAT;
	fe_feature |= HNAT_WAN_P4;
	fe_feature |= WAN_TO_WLAN_QOS;
	fe_feature |= HNAT_SP_TAG;
	fe_feature |= QDMA_TX_RX;
	fe_feature |= PPE_MIB;
	fe_feature |= PACKET_SAMPLING;
	fe_feature |= HNAT_OPENWRT;
	fe_feature |= HNAT_WLAN_QOS;
	fe_feature |= WLAN_OPTIMIZE;
	fe_feature |= UDP_FRAG;
	fe_feature |= AUTO_MODE;
	fe_feature |= SEMI_AUTO_MODE;
	fe_feature |= MANUAL_MODE;
	fe_feature |= PRE_BIND;
	fe_feature |= ACCNT_MAINTAINER;
	fe_feature |= HNAT_IPI;
	fe_feature |= DBG_IPV6_SIP;
	fe_feature |= DBG_IPV4_SIP;
	fe_feature |= DBG_SP;
	fe_feature |= ETH_QOS;
}

/*PPE Enabled: GMAC<->PPE<->CPU*/
/*PPE Disabled: GMAC<->CPU*/
static int32_t ppe_init_mod(void)
{
	struct platform_device *pdev;

	NAT_PRINT("Ralink HW NAT Module Enabled\n");
	hwnat_config_setting();
	fe_feature_setting();
	pr_info("!!!!! hwnat feature = %x\n", fe_feature);
	pr_info("!!!!! chipname = %x\n", hnat_chip_name);
	pdev = platform_device_alloc("HW_NAT", PLATFORM_DEVID_AUTO);
	if (!pdev)
		return -ENOMEM;

	if (hnat_chip_name & (MT7622_HWNAT | LEOPARD_HWNAT)) {
		pdev->dev.coherent_dma_mask = DMA_BIT_MASK(32);
		pdev->dev.dma_mask = &pdev->dev.coherent_dma_mask;
		hwnat_setup_dma_ops(&pdev->dev, FALSE);
	}

	/* Set PPE FOE Hash Mode */
	if (!ppe_setfoe_hash_mode(DFL_FOE_HASH_MODE, &pdev->dev)) {
		pr_info("memory allocation failed\n");
		return -ENOMEM;	/* memory allocation failed */
	}

	/* Get net_device structure of Dest Port */
	ppe_set_dst_port(1);

	/* Register ioctl handler */
	ppe_reg_ioctl_handler();

	ppe_set_ip_prot();
	ppe_set_cache_ebl();
	foe_ac_update_ebl(1);

	/* 0~63 Metering group */
	/* PpeSetMtrByteInfo(1, 500, 3); //TokenRate=500=500KB/s, MaxBkSize= 3 (32K-1B) */
	/* PpeSetMtrPktInfo(1, 5, 3);  //1 pkts/sec, MaxBkSize=3 (32K-1B) */

	/* Initialize PPE related register */
	ppe_eng_start();

	/* In manual mode, PPE always reports UN-HIT CPU reason, so we don't need to process it */
	/* Register RX/TX hook point */
	if (!(fe_feature & MANUAL_MODE)) {
		ra_sw_nat_hook_tx = ppe_tx_handler;
		ra_sw_nat_hook_rx = ppe_rx_handler;
	}
	if (fe_feature & WIFI_HNAT) {
		ppe_dev_register_hook = ppe_dev_reg_handler;
		ppe_dev_unregister_hook = ppe_dev_unreg_handler;
	} else {
		ppe_dev_register_hook = NULL;
		ppe_dev_unregister_hook = NULL;
	}
	/* Set GMAC fowrards packet to PPE */
	set_gdma_fwd(1);

	register_netevent_notifier(&hnat_netevent_nb);
	init_timer(&hwnat_clear_entry_timer);
	hwnat_clear_entry_timer.function = hwnat_clear_entry;
	/*if (fe_feature & HNAT_IPI)*/
	/*	HnatIPIInit();*/
	hnat_debug_proc_init();
	return 0;
}

static void ppe_cleanup_mod(void)
{
	NAT_PRINT("Ralink HW NAT Module Disabled\n");

	/* Set GMAC fowrards packet to CPU */
	set_gdma_fwd(0);

	/* Unregister RX/TX hook point */
	ra_sw_nat_hook_rx = NULL;
	ra_sw_nat_hook_tx = NULL;
	if (fe_feature & WIFI_HNAT) {
		ppe_dev_register_hook = NULL;
		ppe_dev_unregister_hook = NULL;
	}

	/* Restore PPE related register */
	/* ppe_eng_stop(); */
	/* iounmap(ppe_foe_base); */

	/* Unregister ioctl handler */
	ppe_unreg_ioctl_handler();
	foe_ac_update_ebl(0);
	if ((fe_feature & HNAT_QDMA) && (fe_feature & HNAT_MCAST))
		foe_mcast_entry_del_all();

	/* Release net_device structure of Dest Port */
	ppe_set_dst_port(0);

/*	if(fe_feature & HNAT_IPI)*/
/*		HnatIPIDeInit();*/

	unregister_netevent_notifier(&hnat_netevent_nb);
	hnat_debug_proc_exit();
}

module_init(ppe_init_mod);
module_exit(ppe_cleanup_mod);

MODULE_AUTHOR("Steven Liu/Kurtis Ke");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Mediatek Hardware NAT\n");
