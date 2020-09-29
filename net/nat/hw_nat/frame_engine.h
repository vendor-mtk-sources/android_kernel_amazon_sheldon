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
#ifndef _FE_WANTED
#define _FE_WANTED

#include <linux/version.h>
#include "raether.h"

extern void __iomem *ethdma_sysctl_base;
extern struct net_device                *dev_raether;

#define ETHDMASYS_BASE			 ethdma_sysctl_base /* for I2S/PCM/GDMA/HSDMA/FE/GMAC */

#define ETHDMASYS_SYSCTL_BASE           ETHDMASYS_BASE
#define RALINK_FRAME_ENGINE_BASE	ETHDMASYS_FRAME_ENGINE_BASE
#define RALINK_PPE_BASE                 ETHDMASYS_PPE_BASE
#define RALINK_SYSCTL_BASE		ETHDMASYS_SYSCTL_BASE

#define MAC_ARG(x) (((u8 *)(x))[0], ((u8 *)(x))[1], ((u8 *)(x))[2], \
		       ((u8 *)(x))[3], ((u8 *)(x))[4], ((u8 *)(x))[5])

#define IPV6_ADDR(x) (ntohs(x[0]), ntohs(x[1]), ntohs(x[2]), ntohs(x[3]), ntohs(x[4]),\
		     ntohs(x[5]), ntohs(x[6]), ntohs(x[7]))

#define IN
#define OUT
#define INOUT

#define NAT_DEBUG

#ifdef NAT_DEBUG
#define NAT_PRINT(fmt, args...) printk(fmt, ## args)
#else
#define NAT_PRINT(fmt, args...) { }
#endif

#define CHIPID		    (RALINK_SYSCTL_BASE + 0x00)
#define REVID		    (RALINK_SYSCTL_BASE + 0x0C)

#define FOE_TS		    (RALINK_FRAME_ENGINE_BASE + 0x0010)

#define PPE_GLO_CFG	    (RALINK_PPE_BASE + 0x200)
#define PPE_FLOW_CFG	    (RALINK_PPE_BASE + 0x204)
#define PPE_FLOW_SET	    PPE_FLOW_CFG
#define PPE_IP_PROT_CHK	    (RALINK_PPE_BASE + 0x208)
#define PPE_IP_PROT_0	    (RALINK_PPE_BASE + 0x20C)
#define PPE_IP_PROT_1	    (RALINK_PPE_BASE + 0x210)
#define PPE_IP_PROT_2	    (RALINK_PPE_BASE + 0x214)
#define PPE_IP_PROT_3	    (RALINK_PPE_BASE + 0x218)
#define PPE_TB_CFG	    (RALINK_PPE_BASE + 0x21C)
#define PPE_FOE_CFG	    PPE_TB_CFG
#define PPE_TB_BASE	    (RALINK_PPE_BASE + 0x220)
#define PPE_FOE_BASE	    (PPE_TB_BASE)
#define PPE_TB_USED	    (RALINK_PPE_BASE + 0x224)
#define PPE_BNDR	    (RALINK_PPE_BASE + 0x228)
#define PPE_FOE_BNDR	    PPE_BNDR
#define PPE_BIND_LMT_0	    (RALINK_PPE_BASE + 0x22C)
#define PPE_FOE_LMT1	    (PPE_BIND_LMT_0)
#define PPE_BIND_LMT_1	    (RALINK_PPE_BASE + 0x230)
#define PPE_FOE_LMT2	    PPE_BIND_LMT_1
#define PPE_KA		    (RALINK_PPE_BASE + 0x234)
#define PPE_FOE_KA	    PPE_KA
#define PPE_UNB_AGE	    (RALINK_PPE_BASE + 0x238)
#define PPE_FOE_UNB_AGE	    PPE_UNB_AGE
#define PPE_BND_AGE_0	    (RALINK_PPE_BASE + 0x23C)
#define PPE_FOE_BND_AGE0    PPE_BND_AGE_0
#define PPE_BND_AGE_1	    (RALINK_PPE_BASE + 0x240)
#define PPE_FOE_BND_AGE1    PPE_BND_AGE_1
#define PPE_HASH_SEED	    (RALINK_PPE_BASE + 0x244)

#if defined(CONFIG_ARCH_MT7622) || defined(CONFIG_MACH_LEOPARD)
#define PPE_MCAST_L_10       (RALINK_PPE_BASE + 0x00)
#define PPE_MCAST_H_10       (RALINK_PPE_BASE + 0x04)
#else
#define PPE_MCAST_L_10       (RALINK_PPE_BASE + 0x288)
#define PPE_MCAST_H_10       (RALINK_PPE_BASE + 0x28c)
#endif

#define PPE_DFT_CPORT       (RALINK_PPE_BASE + 0x248)
#define PPE_MCAST_PPSE	    (RALINK_PPE_BASE + 0x284)
#define PPE_MCAST_L_0       (RALINK_PPE_BASE + 0x288)
#define PPE_MCAST_H_0       (RALINK_PPE_BASE + 0x28C)
#define PPE_MCAST_L_1       (RALINK_PPE_BASE + 0x290)
#define PPE_MCAST_H_1       (RALINK_PPE_BASE + 0x294)
#define PPE_MCAST_L_2       (RALINK_PPE_BASE + 0x298)
#define PPE_MCAST_H_2       (RALINK_PPE_BASE + 0x29C)
#define PPE_MCAST_L_3       (RALINK_PPE_BASE + 0x2A0)
#define PPE_MCAST_H_3       (RALINK_PPE_BASE + 0x2A4)
#define PPE_MCAST_L_4       (RALINK_PPE_BASE + 0x2A8)
#define PPE_MCAST_H_4       (RALINK_PPE_BASE + 0x2AC)
#define PPE_MCAST_L_5       (RALINK_PPE_BASE + 0x2B0)
#define PPE_MCAST_H_5       (RALINK_PPE_BASE + 0x2B4)
#define PPE_MCAST_L_6       (RALINK_PPE_BASE + 0x2BC)
#define PPE_MCAST_H_6       (RALINK_PPE_BASE + 0x2C0)
#define PPE_MCAST_L_7       (RALINK_PPE_BASE + 0x2C4)
#define PPE_MCAST_H_7       (RALINK_PPE_BASE + 0x2C8)
#define PPE_MCAST_L_8       (RALINK_PPE_BASE + 0x2CC)
#define PPE_MCAST_H_8       (RALINK_PPE_BASE + 0x2D0)
#define PPE_MCAST_L_9       (RALINK_PPE_BASE + 0x2D4)
#define PPE_MCAST_H_9       (RALINK_PPE_BASE + 0x2D8)
#define PPE_MCAST_L_A       (RALINK_PPE_BASE + 0x2DC)
#define PPE_MCAST_H_A       (RALINK_PPE_BASE + 0x2E0)
#define PPE_MCAST_L_B       (RALINK_PPE_BASE + 0x2E4)
#define PPE_MCAST_H_B       (RALINK_PPE_BASE + 0x2E8)
#define PPE_MCAST_L_C       (RALINK_PPE_BASE + 0x2EC)
#define PPE_MCAST_H_C       (RALINK_PPE_BASE + 0x2F0)
#define PPE_MCAST_L_D       (RALINK_PPE_BASE + 0x2F4)
#define PPE_MCAST_H_D       (RALINK_PPE_BASE + 0x2F8)
#define PPE_MCAST_L_E       (RALINK_PPE_BASE + 0x2FC)
#define PPE_MCAST_H_E       (RALINK_PPE_BASE + 0x2E0)
#define PPE_MCAST_L_F       (RALINK_PPE_BASE + 0x300)
#define PPE_MCAST_H_F       (RALINK_PPE_BASE + 0x304)
#define PPE_MTU_DRP         (RALINK_PPE_BASE + 0x308)
#define PPE_MTU_VLYR_0      (RALINK_PPE_BASE + 0x30C)
#define PPE_MTU_VLYR_1      (RALINK_PPE_BASE + 0x310)
#define PPE_MTU_VLYR_2      (RALINK_PPE_BASE + 0x314)
#define PPE_VPM_TPID        (RALINK_PPE_BASE + 0x318)

#define CAH_CTRL	    (RALINK_PPE_BASE + 0x320)
#define CAH_TAG_SRH         (RALINK_PPE_BASE + 0x324)
#define CAH_LINE_RW         (RALINK_PPE_BASE + 0x328)
#define CAH_WDATA           (RALINK_PPE_BASE + 0x32C)
#define CAH_RDATA           (RALINK_PPE_BASE + 0x330)

#define PS_CFG	            (RALINK_PPE_BASE + 0x400)
#define PS_FBC		    (RALINK_PPE_BASE + 0x404)
#define PS_TB_BASE	    (RALINK_PPE_BASE + 0x408)
#define PS_TME_SMP	    (RALINK_PPE_BASE + 0x40C)

#define MIB_CFG		    (RALINK_PPE_BASE + 0x334)
#define MIB_TB_BASE	    (RALINK_PPE_BASE + 0x338)
#define MIB_SER_CR	    (RALINK_PPE_BASE + 0x33C)
#define MIB_SER_R0	    (RALINK_PPE_BASE + 0x340)
#define MIB_SER_R1	    (RALINK_PPE_BASE + 0x344)
#define MIB_SER_R2	    (RALINK_PPE_BASE + 0x348)
#define MIB_CAH_CTRL	    (RALINK_PPE_BASE + 0x350)

/*CAH_RDATA[17:16] */
/*0: invalid */
/*1: valid */
/*2: dirty */
/*3: lock */
/*CAH_RDATA[15:0]: entry num*/
/* #define CAH_RDATA	    RALINK_PPE_BASE + 0x330 */
/* TO PPE */
#define IPV4_PPE_MYUC	    BIT(0) /* my mac */
#define IPV4_PPE_MC	    BIT(1) /* multicast */
#define IPV4_PPE_IPM	    BIT(2) /* ip multicast */
#define IPV4_PPE_BC	    BIT(3) /* broadcast */
#define IPV4_PPE_UC	    BIT(4) /* ipv4 learned UC frame */
#define IPV4_PPE_UN	    BIT(5) /* ipv4 unknown  UC frame */

#define IPV6_PPE_MYUC	    BIT(8) /* my mac */
#define IPV6_PPE_MC	    BIT(9) /* multicast */
#define IPV6_PPE_IPM	    BIT(10) /* ipv6 multicast */
#define IPV6_PPE_BC	    BIT(11) /* broadcast */
#define IPV6_PPE_UC	    BIT(12) /* ipv6 learned UC frame */
#define IPV6_PPE_UN	    BIT(13) /* ipv6 unknown  UC frame */

#define AC_BASE		    (RALINK_FRAME_ENGINE_BASE + 0x2000)
#define METER_BASE	    (RALINK_FRAME_ENGINE_BASE + 0x2000)

#define FE_GDMA1_FWD_CFG    (RALINK_FRAME_ENGINE_BASE + 0x500)
#define FE_GDMA2_FWD_CFG    (RALINK_FRAME_ENGINE_BASE + 0x1500)

/* GDMA1 My MAC unicast frame destination port */
#if defined(CONFIG_RAETH_QDMATX_QDMARX)
#define GDM1_UFRC_P_CPU     (5 << 12)
#else
#define GDM1_UFRC_P_CPU     (0 << 12)
#endif
#define GDM1_UFRC_P_PPE     (4 << 12)

/* GDMA1 broadcast frame MAC address destination port */
#if defined(CONFIG_RAETH_QDMATX_QDMARX)
#define GDM1_BFRC_P_CPU     (5 << 8)
#else
#define GDM1_BFRC_P_CPU     (0 << 8)
#endif
#define GDM1_BFRC_P_PPE     (4 << 8)

/* GDMA1 multicast frame MAC address destination port */
#if defined(CONFIG_RAETH_QDMATX_QDMARX)
#define GDM1_MFRC_P_CPU     (5 << 4)
#else
#define GDM1_MFRC_P_CPU     (0 << 4)
#endif
#define GDM1_MFRC_P_PPE     (4 << 4)

/* GDMA1 other MAC address frame destination port */
#if defined(CONFIG_RAETH_QDMATX_QDMARX)
#define GDM1_OFRC_P_CPU     (5 << 0)
#else
#define GDM1_OFRC_P_CPU     (0 << 0)
#endif
#define GDM1_OFRC_P_PPE     (4 << 0)

enum FOE_SMA {
	DROP = 0,		/* Drop the packet */
	DROP2 = 1,		/* Drop the packet */
	ONLY_FWD_CPU = 2,	/* Only Forward to CPU */
	FWD_CPU_BUILD_ENTRY = 3	/* Forward to CPU and build new FOE entry */
};

enum BIND_DIR {
	UPSTREAM_ONLY = 0,	/* only speed up upstream flow */
	DOWNSTREAM_ONLY = 1,	/* only speed up downstream flow */
	BIDIRECTION = 2		/* speed up bi-direction flow */
};

/* PPE_GLO_CFG, Offset=0x200 */
#define DFL_TTL0_DRP		(0)	/* 1:Drop, 0: Alert CPU */
/* PPE Flow Set*/
#define BIT_FBC_FOE		BIT(0)	/* PPE engine for broadcast flow */
#define BIT_FMC_FOE		BIT(1)	/* PPE engine for multicast flow */
#define BIT_FUC_FOE		BIT(2)	/* PPE engine for multicast flow */
#define BIT_UDP_IP4F_NAT_EN	BIT(7)  /*Enable IPv4 fragment + UDP packet NAT*/
#define BIT_IPV6_3T_ROUTE_EN	BIT(8)	/* IPv6 3-tuple route */
#define BIT_IPV6_5T_ROUTE_EN	BIT(9)	/* IPv6 5-tuple route */
#define BIT_IPV6_6RD_EN		BIT(10)	/* IPv6 6RD */
#define BIT_IPV4_NAT_EN		BIT(12)	/* IPv4 NAT */
#define BIT_IPV4_NAPT_EN	BIT(13)	/* IPv4 NAPT */
#define BIT_IPV4_DSL_EN		BIT(14)	/* IPv4 DS-Lite */
#define BIT_IP_PROT_CHK_BLIST	BIT(16)	/* IP protocol check is black/white list */
#define BIT_IPV4_NAT_FRAG_EN	BIT(17)	/* Enable fragment support for IPv4 NAT flow */
#define BIT_IPV6_HASH_FLAB	BIT(18)
/* For IPv6 5-tuple and 6RD flow, using flow label instead of sport and dport to do HASH */
#define BIT_IPV4_HASH_GREK	BIT(19)	/* For IPv4 NAT, adding GRE key into HASH */
#define BIT_IPV6_HASH_GREK	BIT(20)	/* For IPv6 3-tuple, adding GRE key into HASH */

#define IS_IPV6_FLAB_EBL()	((reg_read(PPE_FLOW_SET) & BIT_IPV6_HASH_FLAB) ? 1 : 0)

/* PPE FOE Bind Rate*/
/* packet in a time stamp unit */
#define DFL_FOE_BNDR		CONFIG_RA_HW_NAT_BINDING_THRESHOLD
/*config  RA_HW_NAT_PBND_RD_LMT*/
/*        int "max retyr count"*/
/*	default 10*/
/*	depends on RA_HW_NAT_PREBIND*/
#define DFL_PBND_RD_LMT		10
/*config  RA_HW_NAT_PBND_RD_PRD*/
/*int "check interval in pause state (us) Max:65535"*/
/*	default 1000*/
/*	depends on RA_HW_NAT_PREBIND*/
#define DFL_PBND_RD_PRD		1000

/* PPE_FOE_LMT */
/* smaller than 1/4 of total entries */
#define DFL_FOE_QURT_LMT	16383 /* CONFIG_RA_HW_NAT_QURT_LMT */

/* between 1/2 and 1/4 of total entries */
#define DFL_FOE_HALF_LMT	16383 /* CONFIG_RA_HW_NAT_HALF_LMT */

/* between full and 1/2 of total entries */
#define DFL_FOE_FULL_LMT	16383 /* CONFIG_RA_HW_NAT_FULL_LMT */

/* PPE_FOE_KA*/
/* visit a FOE entry every FOE_KA_T * 1 msec */
#define DFL_FOE_KA_T		1

#if defined(CONFIG_RA_HW_NAT_TBL_1K)
/* FOE_TCP_KA * FOE_KA_T * FOE_4TB_SIZ */
/*TCP KeepAlive Interval(Unit:1Sec)*/
#define DFL_FOE_TCP_KA		5
/* FOE_UDP_KA * FOE_KA_T * FOE_4TB_SIZ */
/*UDP KeepAlive Interval(Unit:1Sec)*/
#define DFL_FOE_UDP_KA		5
/* FOE_NTU_KA * FOE_KA_T * FOE_4TB_SIZ */
/*Non-TCP/UDP KeepAlive Interval(Unit:1Sec)*/
#define DFL_FOE_NTU_KA		5
#elif defined(CONFIG_RA_HW_NAT_TBL_2K)
/*(Unit:2Sec)*/
#define DFL_FOE_TCP_KA		3
#define DFL_FOE_UDP_KA		3
#define DFL_FOE_NTU_KA		3
#elif defined(CONFIG_RA_HW_NAT_TBL_4K)
/*(Unit:4Sec)*/
#define DFL_FOE_TCP_KA		1
#define DFL_FOE_UDP_KA		1
#define DFL_FOE_NTU_KA		1
#elif defined(CONFIG_RA_HW_NAT_TBL_8K)
/*(Unit:8Sec)*/
#define DFL_FOE_TCP_KA		1
#define DFL_FOE_UDP_KA		1
#define DFL_FOE_NTU_KA		1
#elif defined(CONFIG_RA_HW_NAT_TBL_16K)
/*(Unit:16Sec)*/
#define DFL_FOE_TCP_KA		1
#define DFL_FOE_UDP_KA		1
#define DFL_FOE_NTU_KA		1
#elif defined(CONFIG_RA_HW_NAT_TBL_32K)
/*(Unit:16Sec)*/
#define DFL_FOE_TCP_KA		1
#define DFL_FOE_UDP_KA		1
#define DFL_FOE_NTU_KA		1
#endif

/*PPE_FOE_CFG*/
#if defined(CONFIG_RA_HW_NAT_HASH0)
#define DFL_FOE_HASH_MODE	0
#elif defined(CONFIG_RA_HW_NAT_HASH1)
#define DFL_FOE_HASH_MODE	1
#elif defined(CONFIG_RA_HW_NAT_HASH2)
#define DFL_FOE_HASH_MODE	2
#elif defined(CONFIG_RA_HW_NAT_HASH3)
#define DFL_FOE_HASH_MODE	3
#elif defined(CONFIG_RA_HW_NAT_HASH_DBG)
#define DFL_FOE_HASH_MODE	0 /* don't care */
#endif

#define HASH_SEED		0x12345678
#define DFL_FOE_UNB_AGE		1	/* Unbind state age enable */
#define DFL_FOE_TCP_AGE		1	/* Bind TCP age enable */
#define DFL_FOE_NTU_AGE		1	/* Bind TCP age enable */
#define DFL_FOE_UDP_AGE		1	/* Bind UDP age enable */
#define DFL_FOE_FIN_AGE		1	/* Bind TCP FIN age enable */
#define DFL_FOE_KA		3	/* 0:disable 1:unicast old 2: multicast new 3. duplicate old */

/*PPE_FOE_UNB_AGE*/
/*The min threshold of packet count for aging out at unbind state */
/*An unbind flow whose pkt counts < Min threshold and idle time > Life time*/
/*=> This unbind entry would be aged out*/
/*[Notes: Idle time = current time - last packet receive time] (Pkt count)*/
#define DFL_FOE_UNB_MNP		1000
/* Delta time for aging out an unbind FOE entry */
/*set ageout time for bind Unbind entry(Unit:1Sec)*/
#define DFL_FOE_UNB_DLTA	3
/* Delta time for aging out an bind Non-TCP/UDP FOE entry */
#define DFL_FOE_NTU_DLTA	5

/* PPE_FOE_BND_AGE1*/
/* Delta time for aging out an bind UDP FOE entry */
/*Set ageout time for bind UDP entry(Unit:1Sec)*/
#define DFL_FOE_UDP_DLTA	5

/*PPE_FOE_BND_AGE2*/
/* Delta time for aging out an bind TCP FIN entry */
/*Set ageout time for FIN entry*/
#define DFL_FOE_FIN_DLTA	5
/* Delta time for aging out an bind TCP entry */
/*Set ageout time for bind TCP entry (Unit:1Sec)*/
#define DFL_FOE_TCP_DLTA	5

#define DFL_FOE_TTL_REGEN	1	/* TTL = TTL -1 */

#endif
