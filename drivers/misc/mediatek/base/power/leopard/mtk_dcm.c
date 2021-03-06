/*
 * Copyright (C) 2018 MediaTek Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) "[Power/dcm] " fmt

#include <linux/bug.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <mt-plat/sync_write.h>
#include "mtk_dcm.h"

/* #define DCM_DEFAULT_ALL_OFF */
enum {
	ARMCORE_DCM = 0,
	INFRA_DCM,
	PERI_DCM,
	EMI_DCM,
	DRAMC_DCM,
	TOPCKG_DCM,
	NR_DCM
};

enum {
	ARMCORE_DCM_TYPE = (1U << 0),
	INFRA_DCM_TYPE = (1U << 1),
	PERI_DCM_TYPE = (1U << 2),
	EMI_DCM_TYPE = (1U << 3),
	DRAMC_DCM_TYPE = (1U << 4),
	TOPCKG_DCM_TYPE = (1U << 5),
	NR_DCM_TYPE = 6,
};

static void __iomem *subsys_base[NR_DCM];
static char *subsys_compatible_node[NR_DCM] = {
	"mediatek,leopard-apmixedsys",
	"mediatek,leopard-infracfg",
	"mediatek,leopard-pericfg",
	"mediatek,leopard-emi",
	"mediatek,leopard-dramc",
	"mediatek,leopard-topckgen",
};

#define APMIXED_BASE		(subsys_base[ARMCORE_DCM])	/* 0xF0209000 */
#define INFRACFG_AO_BASE	(subsys_base[INFRA_DCM])	/* 0xF0000000 */
#define PERICFG_BASE		(subsys_base[PERI_DCM])		/* 0xF0002000 */
#define EMI_REG_BASE		(subsys_base[EMI_DCM])		/* 0xF0203000 */
#define DRAMC_AO_BASE		(subsys_base[DRAMC_DCM])	/* 0xF0214000 */
#define TOPCKGEN_BASE		(subsys_base[TOPCKG_DCM])	/* 0xF0210000 */

/* INFRASYS_AO */
#define INFRA_TOPCKGEN_DCMCTL  (INFRACFG_AO_BASE + 0x010)	/* 0x10000010 */
#define INFRA_GLOBALCON_DCMCTL (INFRACFG_AO_BASE + 0x050)	/* 0x10000050 */
#define INFRA_GLOBALCON_DCMDBC (INFRACFG_AO_BASE + 0x054)	/* 0x10000054 */
#define INFRA_GLOBALCON_DCMFSEL (INFRACFG_AO_BASE + 0x058)	/* 0x10000058 */

/* TOPCKGEN */
#define TOPCKG_DCM_CFG (TOPCKGEN_BASE + 0x4)	/* 0x10210004 */
#define TOPCKG_CLK_MISC_CFG_1 (TOPCKGEN_BASE + 0x214)	/* 0x10210214 */

/* perisys */
#define PERI_GLOBALCON_DCMCTL (PERICFG_BASE + 0x050)	/* 0x10002050 */
#define PERI_GLOBALCON_DCMDBC (PERICFG_BASE + 0x054)	/* 0x10002054 */
#define PERI_GLOBALCON_DCMFSEL (PERICFG_BASE + 0x058)	/* 0x10002058 */

/* DRAMC_AO */
#define DRAMC_PD_CTRL   (DRAMC_AO_BASE + 0x38)	/* 0x10214038 */

/* EMI */
#define EMI_CONM        (EMI_REG_BASE + 0x060)	/* 0x10203060 */

/** macro **/
#define and(v, a) ((v) & (a))
#define or(v, o) ((v) | (o))
#define aor(v, a, o) (((v) & (a)) | (o))

#define reg_read(addr)         __raw_readl(addr)
#define reg_write(addr, val)   mt_reg_sync_writel((val), ((void *)addr))

#define REG_DUMP(addr) pr_warn("%-30s(0x%p): 0x%08X\n", #addr, addr, reg_read(addr))

#define DCM_OFF (0)
#define DCM_ON (1)

/** global **/
static DEFINE_MUTEX(dcm_lock);
static int dcm_initiated;

/*****************************************
 * following is implementation per DCM module.
 * 1. per-DCM function is 1-argu with ON/OFF/MODE option.
 *****************************************/
typedef int (*DCM_FUNC) (int);

/** 0x10000014	INFRA_TOPCKGEN_DCMDBC
 * 6	0	topckgen_dcm_dbc_cnt.
 * BUT, this field does not behave as its name.
 * only topckgen_dcm_dbc_cnt[0] is using as ARMPLL DCM mode 1 switch.
 **/

/** 0x10000010	INFRA_TOPCKGEN_DCMCTL
 * 1	1	arm_dcm_wfi_enable
 * 2	2	arm_dcm_wfe_enable
 **/

typedef enum {
	ARMCORE_DCM_OFF = DCM_OFF,
	ARMCORE_DCM_MODE1 = DCM_ON,
	ARMCORE_DCM_MODE2 = DCM_ON + 1,
} ENUM_ARMCORE_DCM;

/** 0x0000	INFRA_TOP_CKMUXSEL
 * 3	2	mux1_sel         * "00: CLKSQ, 01: ARMPLL, 10: MAINPLL, 11: 1'b0"
 **/

/** 0x0008	INFRA_TOP_CKDIV1
 * 4	0	clkdiv1_sel
 **/

int dcm_armcore_pll_clkdiv(int pll, int div)
{
	return 0;
}

int dcm_armcore(ENUM_ARMCORE_DCM mode)
{
	return 0;
}

/** 0x10210004	DCM_CFG
 * 4	0	dcm_full_fsel (axi bus dcm full fsel)
 * 7	7	dcm_enable
 * 14	8	dcm_dbc_cnt
 * 15	15	dcm_dbc_enable
 * 20	16	mem_dcm_full_fsel ("1xxxx:1/1, 01xxx:1/2, 001xx: 1/4, 0001x: 1/8, 00001: 1/16, 00000: 1/32")
 * 21	21	mem_dcm_cfg_latch
 * 22	22	mem_dcm_idle_align
 * 23	23	mem_dcm_enable
 * 30	24	mem_dcm_dbc_cnt
 * 31	31	mem_dcm_dbc_enable
 **/
#define TOPCKG_DCM_CFG_MASK     0x00A00080
#define TOPCKG_DCM_CFG_ON       0x00A00080
#define TOPCKG_DCM_CFG_OFF      0
/* Used for slow idle to enable or disable TOPCK DCM */
#define TOPCKG_DCM_CFG_QMASK     (1<<7)
#define TOPCKG_DCM_CFG_QON       (1<<7)
#define TOPCKG_DCM_CFG_QOFF      (0<<7)

#define TOPCKG_DCM_CFG_FMEM_MASK            ((0x1f<<16) | (1<<21) | (1<<22) \
					     | (1<<23) | (0x7f<<24) | (1<<31))
#define TOPCKG_DCM_CFG_FMEM_ON              ((0<<16) | (1<<21) | (0x0<<22) \
					     | (1<<23) | (0<<24) | (0<<31))
#define TOPCKG_DCM_CFG_FMEM_OFF             ((0<<21) | (0<<23))
/* toggle mem_dcm_cfg_latch since it's triggered by rising edge */
#define TOPCKG_DCM_CFG_FMEM_TOGGLE_MASK     (1<<21)
#define TOPCKG_DCM_CFG_FMEM_TOGGLE_CLEAR    (0<<21)
#define TOPCKG_DCM_CFG_FMEM_TOGGLE_ON       (1<<21)

/** TOPCKG_CLK_MISC_CFG_2
 * 7   0   mem_dcm_force_idle (0: does not force idle, 1: force idle to high)
 **/
#define TOPCKG_CLK_MISC_CFG_2_MASK     (0xf<<0)
#define TOPCKG_CLK_MISC_CFG_2_ON       (0xf<<0)
#define TOPCKG_CLK_MISC_CFG_2_OFF      (0x0<<0)

/** 0x10000010	INFRA_TOPCKGEN_DCMCTL
 * 0	0	infra_dcm_enable
 * this field actually is to activate clock ratio between infra/fast_peri/slow_peri.
 * and need to set when bus clock switch from CLKSQ to PLL.
 * do ASSERT, for each time infra/peri bus dcm setting.
 **/
#define ASSERT_INFRA_DCMCTL() \
	do {      \
		volatile unsigned int dcmctl;                           \
		dcmctl = reg_read(INFRA_TOPCKGEN_DCMCTL);               \
		WARN_ON(!(dcmctl & 1));                                  \
	} while (0)

/** 0x10000050	INFRA_GLOBALCON_DCMCTL
 * 0	0	faxi_dcm_enable
 * 1	1	fmem_dcm_enable
 * 8	8	axi_clock_gated_en
 * 9	9	l2c_sram_infra_dcm_en
 **/
#define INFRA_GLOBALCON_DCMCTL_MASK     (0x00000303)
#define INFRA_GLOBALCON_DCMCTL_ON       (0x00000303)
#define INFRA_GLOBALCON_DCMCTL_OFF      (0x00000000)


/** 0x10000054	INFRA_GLOBALCON_DCMDBC
 * 6	0	dcm_dbc_cnt (default 7'h7F)
 * 8	8	faxi_dcm_dbc_enable
 * 22	16	dcm_dbc_cnt_fmem (default 7'h7F)
 * 24	24	dcm_dbc_enable_fmem
 **/
#define INFRA_GLOBALCON_DCMDBC_MASK  ((0x7f<<0) | (1<<8) | (0x7f<<16) | (1<<24))
#define INFRA_GLOBALCON_DCMDBC_ON      ((0<<0) | (1<<8) | (0<<16) | (1<<24))
#define INFRA_GLOBALCON_DCMDBC_OFF     INFRA_GLOBALCON_DCMDBC_ON	/* dont-care */


/** 0x10000058	INFRA_GLOBALCON_DCMFSEL
 * 2	0	dcm_qtr_fsel ("1xx: 1/4, 01x: 1/8, 001: 1/16, 000: 1/32")
 * 11	8	dcm_half_fsel ("1xxx:1/2, 01xx: 1/4, 001x: 1/8, 0001: 1/16, 0000: 1/32")
 * 20	16	dcm_full_fsel ("1xxxx:1/1, 01xxx:1/2, 001xx: 1/4, 0001x: 1/8, 00001: 1/16, 00000: 1/32")
 * 28	24	dcm_full_fsel_fmem ("1xxxx:1/1, 01xxx:1/2, 001xx: 1/4, 0001x: 1/8, 00001: 1/16, 00000: 1/32")
 **/
#define INFRA_GLOBALCON_DCMFSEL_MASK ((0x7<<0) | (0x7<<8) | (0x1f<<16) | (0x1f<<24))
#define INFRA_GLOBALCON_DCMFSEL_ON ((0<<0) | (0<<8) | (0x10<<16) | (0x10<<24))
#define INFRA_GLOBALCON_DCMFSEL_OFF (INFRA_GLOBALCON_DCMFSEL_ON)	/* dont-care */


typedef enum {
	TOPCKG_DCM_OFF = DCM_OFF,
	TOPCKG_DCM_ON = DCM_ON,
} ENUM_TOPCKG_DCM;

typedef enum {
	INFRA_DCM_OFF = DCM_OFF,
	INFRA_DCM_ON = DCM_ON,
} ENUM_INFRA_DCM;


int dcm_topckg_dbc(int on, int cnt)
{
	return 0;
}

/** input argument
 * 0: 1/1
 * 1: 1/2
 * 2: 1/4
 * 3: 1/8
 * 4: 1/16
 * 5: 1/32
 **/
int dcm_topckg_rate(unsigned int fmem, unsigned int faxi)
{
	return 0;
}

/** FMEM DCM enable or disable (separate fmem DCM setting from TOPCK)
 *  For writing reg successfully, we need to toggle mem_dcm_cfg_latch first.
 **/
int dcm_fmem(ENUM_TOPCKG_DCM on)
{
	return 0;
}

int dcm_topckg(ENUM_TOPCKG_DCM on)
{
	if (on) {
		reg_write(TOPCKG_DCM_CFG, aor(reg_read(TOPCKG_DCM_CFG),
					      ~TOPCKG_DCM_CFG_MASK, TOPCKG_DCM_CFG_ON));
	} else {
		reg_write(TOPCKG_DCM_CFG, aor(reg_read(TOPCKG_DCM_CFG),
					      ~TOPCKG_DCM_CFG_MASK, TOPCKG_DCM_CFG_OFF));
	}

	return 0;
}

/* cnt : 0~0x7f */
int dcm_infra_dbc(int on, int cnt)
{
	return 0;
}

/** input argument
 * 0: 1/1
 * 1: 1/2
 * 2: 1/4
 * 3: 1/8
 * 4: 1/16
 * 5: 1/32
 **/
int dcm_infra_rate(unsigned fmem, unsigned int full, unsigned int half, unsigned int quarter)
{
	return 0;
}

int dcm_infra(ENUM_INFRA_DCM on)
{

	ASSERT_INFRA_DCMCTL();

	if (on) {
		reg_write(INFRA_GLOBALCON_DCMDBC, 0x007F007F);
		reg_write(INFRA_GLOBALCON_DCMFSEL, 0x0);

		reg_write(INFRA_GLOBALCON_DCMCTL,
			  aor(reg_read(INFRA_GLOBALCON_DCMCTL), ~INFRA_GLOBALCON_DCMCTL_MASK,
			      INFRA_GLOBALCON_DCMCTL_ON));
	} else {
		reg_write(INFRA_GLOBALCON_DCMCTL,
			  aor(reg_read(INFRA_GLOBALCON_DCMCTL), ~INFRA_GLOBALCON_DCMCTL_MASK,
			      INFRA_GLOBALCON_DCMCTL_OFF));
	}

	return 0;
}


/** 0x10002050	PERI_GLOBALCON_DCMCTL
 * 0	0	DCM_ENABLE
 * 1	1	AXI_CLOCK_GATED_EN
 * 7	4	AHB_BUS_SLP_REQ
 * 12	8	DCM_IDLE_BYPASS_EN
 **/

/** 0x10002054	PERI_GLOBALCON_DCMDBC
 * 7	7	DCM_DBC_ENABLE
 * 6	0	DCM_DBC_CNT
 **/

/** 0x10002058	PERI_GLOBALCON_DCMFSEL
 * 20	16	DCM_FULL_FSEL
 * 11	8	DCM_HALF_FSEL
 * 2	0	DCM_QTR_FSEL
 **/

#define PERI_GLOBALCON_DCMCTL_MASK  ((1<<0) | (1<<1) | (0xf<<4) | (0xf<<8))
#define PERI_GLOBALCON_DCMCTL_ON  ((1<<0) | (1<<1) | (0xf<<4) | (0x0<<8))
#define PERI_GLOBALCON_DCMCTL_OFF  ((0<<0) | (0<<1) | (0xf<<4) | (0x0<<8))

#define PERI_GLOBALCON_DCMDBC_MASK	0xFF
#define PERI_GLOBALCON_DCMDBC_ON	0xFF
#define PERI_GLOBALCON_DCMDBC_OFF	0x7F

#define PERI_GLOBALCON_DCMFSEL_MASK  ((0x7<<0) | (0xf<<8) | (0x1f<<16))
#define PERI_GLOBALCON_DCMFSEL_ON  ((0<<0) | (0<<8) | (0x0<<16))
#define PERI_GLOBALCON_DCMFSEL_OFF  ((0<<0) | (0<<8) | (0x0<<16))


typedef enum {
	PERI_DCM_OFF = DCM_OFF,
	PERI_DCM_ON = DCM_ON,
} ENUM_PERI_DCM;


/* cnt: 0~0x7f */
int dcm_peri_dbc(int on, int cnt)
{
	return 0;
}

/** input argument
 * 0: 1/1
 * 1: 1/2
 * 2: 1/4
 * 3: 1/8
 * 4: 1/16
 * 5: 1/32
 * default: 5, 5, 5
 **/
int dcm_peri_rate(unsigned int full, unsigned int half, unsigned int quarter)
{
	return 0;
}


int dcm_peri(ENUM_PERI_DCM on)
{

	/* override the dbc and fsel setting !! */
	reg_write(PERI_GLOBALCON_DCMDBC, 0x7F);
	reg_write(PERI_GLOBALCON_DCMFSEL, 0);

	if (on) {
		reg_write(PERI_GLOBALCON_DCMCTL, aor(reg_read(PERI_GLOBALCON_DCMCTL),
			~PERI_GLOBALCON_DCMCTL_MASK, PERI_GLOBALCON_DCMCTL_ON));
	} else {
		reg_write(PERI_GLOBALCON_DCMCTL, aor(reg_read(PERI_GLOBALCON_DCMCTL),
				~PERI_GLOBALCON_DCMCTL_MASK, PERI_GLOBALCON_DCMCTL_OFF));
	}

	return 0;
}


/* 0x10214038	DRAMC_PD_CTRL
 * 31	31	COMBCLKCTRL ("DQPHY clock dynamic gating control
 *		(gating during All-bank Refresh), 1 : controlled by dramc , 0 : always no gating")
 * 30	30	PHYCLKDYNGEN ("CMDPHY clock dynamic gating control, 1 : controlled by dramc, 0 : always no gating")
 * 0	0	DCMEN ("DRAMC non-freerun clock gating function, 0: disable, 1: enable")
 */
typedef enum {
	DRAMC_AO_DCM_OFF = DCM_OFF,
	DRAMC_AO_DCM_ON = DCM_ON,
} ENUM_DRAMC_AO_DCM;

int dcm_dramc_ao(ENUM_DRAMC_AO_DCM on)
{
	if (on)
		reg_write(DRAMC_PD_CTRL, or(reg_read(DRAMC_PD_CTRL), 0x1));
	else
		reg_write(DRAMC_PD_CTRL, aor(reg_read(DRAMC_PD_CTRL), 0xFFFFFFF8, 0x6));

	return 0;
}

/** 0x10203060	EMI_CONM
 * 31	24	EMI_DCM_DIS
 **/
typedef enum {
	EMI_DCM_OFF = DCM_OFF,
	EMI_DCM_ON = DCM_ON,
} ENUM_EMI_DCM;

int dcm_emi(ENUM_EMI_DCM on)
{
	if (on)
		reg_write(EMI_CONM, and(reg_read(EMI_CONM), 0x00FFFFFF));
	else
		reg_write(EMI_CONM, or(reg_read(EMI_CONM), 0xFF000000));

	return 0;
}

/*****************************************************/
/* Do not do infra DCM ON/OFF here due to H/W limitation. Do it on preloader instead */
#define ALL_DCM_TYPE  (ARMCORE_DCM_TYPE | INFRA_DCM_TYPE | PERI_DCM_TYPE | EMI_DCM_TYPE \
								| DRAMC_DCM_TYPE | TOPCKG_DCM_TYPE)

#define INIT_DCM_TYPE  (INFRA_DCM_TYPE | PERI_DCM_TYPE |  EMI_DCM_TYPE \
						| DRAMC_DCM_TYPE | TOPCKG_DCM_TYPE)

typedef struct _dcm {
	int current_state;
	int saved_state;
	int disable_refcnt;
	int default_state;
	DCM_FUNC func;
	int typeid;
	char *name;
} DCM;

static DCM dcm_array[NR_DCM_TYPE] = {
	{
	 .typeid = ARMCORE_DCM_TYPE,
	 .name = "ARMCORE_DCM",
	 .func = (DCM_FUNC) dcm_armcore,
	 .current_state = ARMCORE_DCM_MODE1,
	 .default_state = ARMCORE_DCM_MODE1,
	 .disable_refcnt = 0,
	 },
	{
	 .typeid = INFRA_DCM_TYPE,
	 .name = "INFRA_DCM",
	 .func = (DCM_FUNC) dcm_infra,
	 .current_state = INFRA_DCM_ON,
	 .default_state = INFRA_DCM_ON,
	 .disable_refcnt = 0,
	 },
	{
	 .typeid = PERI_DCM_TYPE,
	 .name = "PERI_DCM",
	 .func = (DCM_FUNC) dcm_peri,
	 .current_state = PERI_DCM_ON,
	 .default_state = PERI_DCM_ON,
	 .disable_refcnt = 0,
	 },
	{
	 .typeid = EMI_DCM_TYPE,
	 .name = "EMI_DCM",
	 .func = (DCM_FUNC) dcm_emi,
	 .current_state = EMI_DCM_ON,
	 .default_state = EMI_DCM_ON,
	 .disable_refcnt = 0,
	 },
	{
	 .typeid = DRAMC_DCM_TYPE,
	 .name = "DRAMC_DCM",
	 .func = (DCM_FUNC) dcm_dramc_ao,
	 .current_state = DRAMC_AO_DCM_ON,
	 .default_state = DRAMC_AO_DCM_ON,
	 .disable_refcnt = 0,
	 },
	{
	 .typeid = TOPCKG_DCM_TYPE,
	 .name = "TOPCKG_DCM",
	 .func = (DCM_FUNC) dcm_topckg,
	 .current_state = TOPCKG_DCM_ON,
	 .default_state = TOPCKG_DCM_ON,
	 .disable_refcnt = 0,
	 },
};

/*****************************************
 * DCM driver will provide regular APIs :
 * 1. dcm_restore(type) to recovery CURRENT_STATE before any power-off reset.
 * 2. dcm_set_default(type) to reset as cold-power-on init state.
 * 3. dcm_disable(type) to disable all dcm.
 * 4. dcm_set_state(type) to set dcm state.
 * 5. dcm_dump_state(type) to show CURRENT_STATE.
 * 6. /sys/power/dcm_state interface:  'restore', 'disable', 'dump', 'set'. 4 commands.
 *
 * spsecified APIs for workaround:
 * 1. (definitely no workaround now)
 *****************************************/
void dcm_set_default(unsigned int type)
{
	int i;
	DCM *dcm;

	mutex_lock(&dcm_lock);

	for (i = 0, dcm = &dcm_array[0]; i < NR_DCM_TYPE; i++, dcm++) {
		if (type & dcm->typeid) {
			dcm->saved_state = dcm->current_state = dcm->default_state;
			dcm->disable_refcnt = 0;
			dcm->func(dcm->current_state);
		}
	}

	mutex_unlock(&dcm_lock);
}

void dcm_set_state(unsigned int type, int state)
{
	int i;
	DCM *dcm;

	pr_debug("[%s]type:0x%08x, set:%d\n", __func__, type, state);

	mutex_lock(&dcm_lock);

	for (i = 0, dcm = &dcm_array[0]; type && (i < NR_DCM_TYPE); i++, dcm++) {
		if (type & dcm->typeid) {
			type &= ~(dcm->typeid);

			dcm->saved_state = state;
			if (dcm->disable_refcnt == 0) {
				dcm->current_state = state;
				dcm->func(dcm->current_state);
			}
			pr_debug("[%16s 0x%08x] current state:%d (%d)\n",
				 dcm->name, dcm->typeid, dcm->current_state, dcm->disable_refcnt);
		}
	}

	mutex_unlock(&dcm_lock);
}


void dcm_disable(unsigned int type)
{
	int i;
	DCM *dcm;

	pr_debug("[%s]type:0x%08x\n", __func__, type);

	mutex_lock(&dcm_lock);

	for (i = 0, dcm = &dcm_array[0]; type && (i < NR_DCM_TYPE); i++, dcm++) {
		if (type & dcm->typeid) {
			type &= ~(dcm->typeid);

			dcm->current_state = DCM_OFF;
			dcm->disable_refcnt++;
			dcm->func(dcm->current_state);

			pr_debug("[%16s 0x%08x] current state:%d (%d)\n",
				 dcm->name, dcm->typeid, dcm->current_state, dcm->disable_refcnt);
		}
	}

	mutex_unlock(&dcm_lock);

}

void dcm_restore(unsigned int type)
{
	int i;
	DCM *dcm;

	pr_debug("[%s]type:0x%08x\n", __func__, type);

	mutex_lock(&dcm_lock);

	for (i = 0, dcm = &dcm_array[0]; type && (i < NR_DCM_TYPE); i++, dcm++) {
		if (type & dcm->typeid) {
			type &= ~(dcm->typeid);

			if (dcm->disable_refcnt > 0)
				dcm->disable_refcnt--;
			if (dcm->disable_refcnt == 0) {
				dcm->current_state = dcm->saved_state;
				dcm->func(dcm->current_state);
			}
			pr_debug("[%16s 0x%08x] current state:%d (%d)\n",
				 dcm->name, dcm->typeid, dcm->current_state, dcm->disable_refcnt);
		}
	}

	mutex_unlock(&dcm_lock);
}


void dcm_dump_state(int type)
{
	int i;
	DCM *dcm;

	pr_info("\n");
	pr_info("******** dcm dump state *********\n");
	for (i = 0, dcm = &dcm_array[0]; i < NR_DCM_TYPE; i++, dcm++) {
		if (type & dcm->typeid) {
			pr_info("[%-16s 0x%08x] current state:%d (%d)\n",
				 dcm->name, dcm->typeid, dcm->current_state, dcm->disable_refcnt);
		}
	}
}

void dcm_dump_regs(void)
{
	pr_info("\n");
	pr_info("******** dcm dump register *********\n");
	REG_DUMP(INFRA_TOPCKGEN_DCMCTL);
	REG_DUMP(INFRA_GLOBALCON_DCMCTL);
	REG_DUMP(INFRA_GLOBALCON_DCMDBC);
	REG_DUMP(INFRA_GLOBALCON_DCMFSEL);
	REG_DUMP(TOPCKG_DCM_CFG);
	REG_DUMP(PERI_GLOBALCON_DCMCTL);
	REG_DUMP(PERI_GLOBALCON_DCMDBC);
	REG_DUMP(PERI_GLOBALCON_DCMFSEL);
	REG_DUMP(DRAMC_PD_CTRL);
	REG_DUMP(EMI_CONM);
}


#if defined(CONFIG_PM)
static ssize_t dcm_state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	int len = 0;
	int i;
	DCM *dcm;

	/* dcm_dump_state(ALL_DCM_TYPE); */
	len = snprintf(buf, PAGE_SIZE, "\n******** dcm dump state *********\n");
	for (i = 0, dcm = &dcm_array[0]; i < NR_DCM_TYPE; i++, dcm++)
		len += snprintf(buf+len, PAGE_SIZE-len, "[%-16s 0x%08x] current state:%d (%d)\n",
					dcm->name, dcm->typeid, dcm->current_state, dcm->disable_refcnt);

	len += snprintf(buf+len, PAGE_SIZE-len, "\n********** dcm_state help *********\n");
	len += snprintf(buf+len, PAGE_SIZE-len, "set:           echo set [mask] [mode] > /sys/power/dcm_state\n");
	len += snprintf(buf+len, PAGE_SIZE-len, "disable:       echo disable [mask] > /sys/power/dcm_state\n");
	len += snprintf(buf+len, PAGE_SIZE-len, "restore:       echo restore [mask] > /sys/power/dcm_state\n");
	len += snprintf(buf+len, PAGE_SIZE-len, "dump:          echo dump [mask] > /sys/power/dcm_state\n");
	len += snprintf(buf+len, PAGE_SIZE-len, "***** [mask] is hexl bit mask of dcm;\n");
	len += snprintf(buf+len, PAGE_SIZE-len, "***** [mode] is type of DCM to set and retained\n");

	return len;
}

static ssize_t dcm_state_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
			       size_t n)
{
	char cmd[16];
	unsigned int mask;
	int ret, mode;

	if (sscanf(buf, "%15s %x", cmd, &mask) == 2) {
		mask &= ALL_DCM_TYPE;

		if (!strcmp(cmd, "restore")) {
			/* dcm_dump_regs(); */
			dcm_restore(mask);
			/* dcm_dump_regs(); */
		} else if (!strcmp(cmd, "disable")) {
			/* dcm_dump_regs(); */
			dcm_disable(mask);
			/* dcm_dump_regs(); */
		} else if (!strcmp(cmd, "dump")) {
			dcm_dump_state(mask);
			dcm_dump_regs();
		} else if (!strcmp(cmd, "set")) {
			if (sscanf(buf, "%15s %x %d", cmd, &mask, &mode) == 3) {
				mask &= ALL_DCM_TYPE;

				dcm_set_state(mask, mode);
			}
		} else
			pr_warn("SORRY, do not support your command: %s\n", cmd);

		ret = n;
	} else {
		pr_warn("SORRY, do not support your command.\n");
		ret = -EINVAL;
	}

	return ret;
}

static struct kobj_attribute dcm_state_attr = {
	.attr = {
		 .name = "dcm_state",
		 .mode = 0644,
		 },
	.show = dcm_state_show,
	.store = dcm_state_store,
};
#endif				/* #if defined (CONFIG_PM) */

static int mt_dcm_dts_map(void)
{
	struct device_node *node;
	unsigned int subsys_index;

	for (subsys_index = 0; subsys_index < NR_DCM; subsys_index++) {
		node = of_find_compatible_node(NULL, NULL, subsys_compatible_node[subsys_index]);
		if (!node) {
			pr_err("error: cannot find node %s", subsys_compatible_node[subsys_index]);
			WARN_ON(1);
			dcm_initiated = -EINVAL;
			return dcm_initiated;
		}

		subsys_base[subsys_index] = of_iomap(node, 0);
		if (!subsys_base[subsys_index]) {
			pr_err("error: cannot iomap %s", subsys_compatible_node[subsys_index]);
			WARN_ON(1);
			dcm_initiated = -EINVAL;
			return dcm_initiated;
		}
	}

	return 0;
}

int mt_dcm_init(void)
{
	int ret;

	if (dcm_initiated)
		return 0;

	/** workaround **/
	dcm_initiated = 1;

	ret = mt_dcm_dts_map();
	if (ret == -EINVAL)
		return -EINVAL;

#if !defined(DCM_DEFAULT_ALL_OFF)
	/** enable all dcm **/
	dcm_set_default(INIT_DCM_TYPE);
#else /* #if !defined (DCM_DEFAULT_ALL_OFF) */
	dcm_set_state(ALL_DCM_TYPE, DCM_OFF);
#endif /* #if !defined (DCM_DEFAULT_ALL_OFF) */

#if defined(CONFIG_PM)
	{
		int err = 0;

		err = sysfs_create_file(power_kobj, &dcm_state_attr.attr);
		if (err)
			pr_err("[%s]: fail to create sysfs\n", __func__);
	}
#endif /* #if defined (CONFIG_PM) */

	return 0;
}
late_initcall(mt_dcm_init);

#if 0
/**** public APIs *****/
int mt_dcm_disable(void)
{
	mt_dcm_init();
	if (dcm_initiated == -EINVAL)
		return dcm_initiated;

	dcm_disable(ALL_DCM_TYPE);

	return 0;
}
EXPORT_SYMBOL(mt_dcm_disable);

int mt_dcm_restore(void)
{
	mt_dcm_init();
	if (dcm_initiated == -EINVAL)
		return dcm_initiated;

	dcm_restore(ALL_DCM_TYPE);

	return 0;
}
EXPORT_SYMBOL(mt_dcm_restore);

/* mt_dcm_topckg_disable/enable is used for slow idle */
int mt_dcm_topckg_disable(void)
{
	mt_dcm_init();
	if (dcm_initiated == -EINVAL)
		return dcm_initiated;

#if !defined(DCM_DEFAULT_ALL_OFF)
	reg_write(TOPCKG_DCM_CFG, aor(reg_read(TOPCKG_DCM_CFG),
			~TOPCKG_DCM_CFG_QMASK, TOPCKG_DCM_CFG_QOFF));
#endif /* #if !defined (DCM_DEFAULT_ALL_OFF) */

	return 0;
}
EXPORT_SYMBOL(mt_dcm_topckg_disable);

/* mt_dcm_topckg_disable/enable is used for slow idle */
int mt_dcm_topckg_enable(void)
{
	mt_dcm_init();
	if (dcm_initiated == -EINVAL)
		return dcm_initiated;

#if !defined(DCM_DEFAULT_ALL_OFF)
	if (dcm_array[TOPCKG_DCM].current_state != DCM_OFF) {
		reg_write(TOPCKG_DCM_CFG, aor(reg_read(TOPCKG_DCM_CFG),
				~TOPCKG_DCM_CFG_QMASK, TOPCKG_DCM_CFG_QON));
	}
#endif /* #if !defined (DCM_DEFAULT_ALL_OFF) */

	return 0;
}
EXPORT_SYMBOL(mt_dcm_topckg_enable);

int mt_dcm_topck_off(void)
{
	mt_dcm_init();
	if (dcm_initiated == -EINVAL)
		return dcm_initiated;

	dcm_set_state(TOPCKG_DCM_TYPE, DCM_OFF);

	return 0;
}
EXPORT_SYMBOL(mt_dcm_topck_off);

int mt_dcm_topck_on(void)
{
	mt_dcm_init();
	if (dcm_initiated == -EINVAL)
		return dcm_initiated;

	dcm_set_state(TOPCKG_DCM_TYPE, DCM_ON);

	return 0;
}
EXPORT_SYMBOL(mt_dcm_topck_on);

int mt_dcm_peri_off(void)
{
	mt_dcm_init();
	if (dcm_initiated == -EINVAL)
		return dcm_initiated;

	dcm_set_state(PERI_DCM_TYPE, DCM_OFF);

	return 0;
}
EXPORT_SYMBOL(mt_dcm_peri_off);

int mt_dcm_peri_on(void)
{
	mt_dcm_init();
	if (dcm_initiated == -EINVAL)
		return dcm_initiated;

	dcm_set_state(PERI_DCM_TYPE, DCM_ON);

	return 0;
}
EXPORT_SYMBOL(mt_dcm_peri_on);
#endif
