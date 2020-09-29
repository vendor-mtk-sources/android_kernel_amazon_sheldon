ccflags-y += -Idrivers/net/ethernet/raeth
ccflags-y += -Werror
obj-$(CONFIG_RA_HW_NAT) += hw_nat.o

hw_nat-objs := ra_nat.o foe_fdb.o util.o hwnat_ioctl.o api.o mcast_tbl.o
hw_nat-objs += hnat_dbg_proc.o hnat_dbg_api.o

ifeq ($(CONFIG_PINCTRL_MT7622),y)
	EXTRA_CFLAGS += -DCONFIG_ARCH_MT7622
endif

ifeq ($(CONFIG_RALINK),y)
	EXTRA_CFLAGS += -DCONFIG_RALINK_MT7621
endif

ifeq ($(CONFIG_SOC_MT7621),y)
        EXTRA_CFLAGS += -DCONFIG_RALINK_MT7621
endif
