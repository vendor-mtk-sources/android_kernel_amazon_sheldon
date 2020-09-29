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
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/cpu_rmap.h>
#include <net/ra_nat.h>
#include "foe_fdb.h"
hnat_ipi_s *hnat_ipi_from_extif[num_possible_cpus()] ____cacheline_aligned_in_smp;
hnat_ipi_s *hnat_ipi_from_ppehit[num_possible_cpus()] ____cacheline_aligned_in_smp;
hnat_ipi_stat *hnat_ipi_status[num_possible_cpus()] ____cacheline_aligned_in_smp;
/* hnat_ipi_cfg hnat_ipi_config_ctx ____cacheline_aligned_in_smp; */
hnat_ipi_cfg *hnat_ipi_config;/* = &hnat_ipi_config_ctx; */

unsigned int dbg_var;
unsigned int dbg_var2;
struct timer_list ipi_monitor_timer_from_extif;
struct timer_list ipi_monitor_timer_from_ppehit;

int skb_get_rxhash_ipi(struct sk_buff *skb, u32 hflag)
{
	struct rps_dev_flow voidflow, *rflow = &voidflow;
	int cpu;
	unsigned char *old_hdr, *old_data;
	unsigned short old_proto;

	preempt_disable();
	rcu_read_lock();
#if defined(CONFIG_RAETH_QDMA)
	if (hflag & HNAT_IPI_HASH_VTAG) {
		struct vlan_ethhdr *veth;
		u16 vir_if_idx;

		/* veth = (struct vlan_ethhdr *)LAYER2_HEADER(skb); */
		veth = (struct vlan_ethhdr *)skb_mac_header(skb);
		/* something wrong */
		if ((veth->h_vlan_proto != htons(ETH_P_8021Q)) && (veth->h_vlan_proto != 0x5678))
			ipidbg[smp_processor_id()][6]++;

		vir_if_idx = ntohs(veth->h_vlan_TCI);
#if defined(CONFIG_ARCH_MT7622)
		skb->hash = ((u32)vir_if_idx) << (32 - FOE_4TB_BIT);
		skb->l4_hash = 1;
#else
		skb->rxhash = ((u32)vir_if_idx) << (32 - FOE_4TB_BIT);
		skb->l4_rxhash = 1;
#endif
		old_data = skb->data;
		skb->data += 4;
		old_proto = skb->protocol;
		skb->protocol = (*(u16 *)(skb->data - 2));
	}
#endif
	/* old_hdr = skb->network_header; */

	old_hdr = skb_network_header(skb);
	/* old_hdr = skb->data; */
	if (debug_level >= 2) {
		pr_info("00 : skb->head = %p\n", skb->head);
		pr_info("00 : skb->data = %p\n", skb->data);
		pr_info("00 : skb->mac_header = %d\n", skb->mac_header);
		pr_info("00 : skb->network_header = %d\n", skb->network_header);
		pr_info("00 : old_hdr = %p\n", old_hdr);
	}
	cpu = get_rps_cpu(skb->dev, skb, &rflow);
	if (debug_level >= 2) {
		pr_info("11 : skb->head = %p\n", skb->head);
		pr_info("11 : skb->data = %p\n", skb->data);
		pr_info("11 : skb->mac_header = %d\n", skb->mac_header);
		pr_info("11 : skb->network_header = %d\n", skb->network_header);
		pr_info("11 : old_hdr = %p\n", old_hdr);
	}
	if (cpu < 0) {
		cpu = smp_processor_id();
		if (hflag & HNAT_IPI_HASH_FROM_EXTIF)
			ipidbg[cpu][3]++;
		else
			ipidbg2[cpu][3]++;
	}
#if defined(CONFIG_RAETH_QDMA)
	if (hflag & HNAT_IPI_HASH_VTAG) {
		skb->data = old_data;
		skb->protocol = old_proto;
	}
#endif
	/* skb->network_header = old_hdr; */

	skb_set_network_header(skb, (int)(old_hdr - skb->data));
	if (debug_level >= 2) {
		pr_info("22 : skb->head = %p\n", skb->head);
		pr_info("22 : skb->data = %p\n", skb->data);
		pr_info("22 : skb->mac_header = %d\n", skb->mac_header);
		pr_info("22 : skb->network_header = %d\n", skb->network_header);
		pr_info("22 : old_hdr = %p\n", old_hdr);
	}
	rcu_read_unlock();
	preempt_enable();
	return cpu;
}

void smp_func_call_BH_handler_from_extif(unsigned long data)
{
	struct sk_buff *skb_deq;
	unsigned int  cpu_num = smp_processor_id();
	unsigned int re_schedule_cnt = 0;
	unsigned int b_reschedule = 0;
	struct hnat_ipi_s *phnat_ipi = hnat_ipi_from_extif[cpu_num];
	struct hnat_ipi_stat *phnat_ipi_status = hnat_ipi_status[cpu_num];

	atomic_set(&phnat_ipi_status->cpu_status_from_extif, 1);
#if defined(HNAT_IPI_DQ)
	while (skb_queue_len(&phnat_ipi->skb_process_queue) > 0) {
#elif defined(HNAT_IPI_RXQUEUE)
	/* spin_lock(&phnat_ipi->ipilock); */
	while (atomic_read(&phnat_ipi->rx_queue_num) > 0) {
#else
	while ((skb_queue_len(&phnat_ipi->skb_ipi_queue) > 0) && (hnat_ipi_config->enable_from_extif == 1)) {
#endif

#if defined(HNAT_IPI_DQ)
		skb_deq = __skb_dequeue(&phnat_ipi->skb_process_queue);
#elif defined(HNAT_IPI_RXQUEUE)
		skb_deq = phnat_ipi->rx_queue[phnat_ipi->rx_queue_ridx];
		phnat_ipi->rx_queue[phnat_ipi->rx_queue_ridx] = NULL;
		phnat_ipi->rx_queue_ridx = (phnat_ipi->rx_queue_ridx + 1) % 1024;
		atomic_sub(1, &phnat_ipi->rx_queue_num);
#else
		skb_deq = skb_dequeue(&phnat_ipi->skb_ipi_queue);
#endif
		if (skb_deq) {
			ipidbg[cpu_num][8]++;
			ppe_extif_rx_handler(skb_deq);
		} else {
			break;
		}
		re_schedule_cnt++;
		if (re_schedule_cnt > hnat_ipi_config->queue_thresh_from_extif) {
			ipidbg[cpu_num][9]++;
			b_reschedule = 1;
			break;
		}
	}
#if defined(HNAT_IPI_DQ)
	spin_lock(&phnat_ipi->ipilock);
	if (skb_queue_len(&phnat_ipi->skb_process_queue) == 0) {
		unsigned int qlen = skb_queue_len(&phnat_ipi->skb_input_queue);

		if (qlen)
			skb_queue_splice_tail_init(&phnat_ipi->skb_input_queue,
						   &phnat_ipi->skb_process_queue);
	}
	spin_unlock(&phnat_ipi->ipilock);
#endif
#ifdef HNAT_IPI_RXQUEUE
	/* spin_unlock(&phnat_ipi->ipilock); */
#endif

	/* atomic_set(&phnat_ipi_status->cpu_status_from_extif, 0); */
	if (b_reschedule == 1)
		tasklet_hi_schedule(&phnat_ipi->smp_func_call_tsk);
	else
		atomic_set(&phnat_ipi_status->cpu_status_from_extif, 0);
}

static void smp_func_call_from_extif(void *info)
{
	unsigned int cpu = smp_processor_id();
	hnat_ipi_s *phnat_ipi = hnat_ipi_from_extif[cpu];

	phnat_ipi->smp_func_call_tsk.data = cpu;
	ipidbg[cpu][5]++;
	if ((hnat_ipi_config->enable_from_extif == 1) && (phnat_ipi))
		tasklet_hi_schedule(&phnat_ipi->smp_func_call_tsk);
}

void smp_func_call_BH_handler_from_ppehit(unsigned long data)
{
	struct sk_buff *skb_deq;
	unsigned int  cpu_num = smp_processor_id();
	unsigned int re_schedule_cnt = 0;
	struct foe_entry *entry;
	unsigned int b_reschedule = 0;
	struct hnat_ipi_s *phnat_ipi = hnat_ipi_from_ppehit[cpu_num];
	struct hnat_ipi_stat *phnat_ipi_status = hnat_ipi_status[cpu_num];

	atomic_set(&phnat_ipi_status->cpu_status_from_ppehit, 1);
#if defined(HNAT_IPI_DQ)
	while (skb_queue_len(&phnat_ipi->skb_process_queue) > 0) {
#elif defined(HNAT_IPI_RXQUEUE)
	/* spin_lock(&phnat_ipi->ipilock); */
	while (atomic_read(&phnat_ipi->rx_queue_num) > 0) {
#else
	while ((skb_queue_len(&phnat_ipi->skb_ipi_queue) > 0) && (hnat_ipi_config->enable_from_ppehit == 1)) {
#endif
#if defined(HNAT_IPI_DQ)
		skb_deq = __skb_dequeue(&phnat_ipi->skb_process_queue);
#elif defined(HNAT_IPI_RXQUEUE)
		skb_deq = phnat_ipi->rx_queue[phnat_ipi->rx_queue_ridx];
		phnat_ipi->rx_queue[phnat_ipi->rx_queue_ridx] = NULL;
		phnat_ipi->rx_queue_ridx = (phnat_ipi->rx_queue_ridx + 1) % 1024;
		atomic_sub(1, &phnat_ipi->rx_queue_num);
#else
		skb_deq = skb_dequeue(&phnat_ipi->skb_ipi_queue);
#endif
		if (skb_deq) {
#if defined(CONFIG_RAETH_QDMA)
			entry = NULL;
#else
			entry = &ppe_foe_base[FOE_ENTRY_NUM(skb_deq)];
#endif
			hitbind_force_to_cpu_handler(skb_deq, entry);
		} else {
			break;
		}

		re_schedule_cnt++;
		if (re_schedule_cnt > hnat_ipi_config->queue_thresh_from_ppehit) {
			ipidbg2[cpu_num][9]++;
			b_reschedule = 1;
			break;
		}
	}

#if defined(HNAT_IPI_DQ)
	spin_lock(&phnat_ipi->ipilock);
	if (skb_queue_len(&phnat_ipi->skb_process_queue) == 0) {
		unsigned int qlen = skb_queue_len(&phnat_ipi->skb_input_queue);

		if (qlen)
			skb_queue_splice_tail_init(&phnat_ipi->skb_input_queue,
						   &phnat_ipi->skb_process_queue);
	}
	spin_unlock(&phnat_ipi->ipilock);
#endif
#ifdef HNAT_IPI_RXQUEUE
	/* spin_unlock(&phnat_ipi->ipilock); */
#endif

	/* atomic_set(&phnat_ipi_status->cpu_status_from_ppehit, 0); */
	if (b_reschedule == 1)
		tasklet_hi_schedule(&phnat_ipi->smp_func_call_tsk);
	else
		atomic_set(&phnat_ipi_status->cpu_status_from_ppehit, 0);
}

static void smp_func_call_from_ppehit(void *info)
{
	unsigned int cpu = smp_processor_id();
	struct hnat_ipi_s *phnat_ipi = hnat_ipi_from_ppehit[cpu];

	phnat_ipi->smp_func_call_tsk.data = cpu;
	ipidbg2[cpu][5]++;
	if ((hnat_ipi_config->enable_from_ppehit == 1) && phnat_ipi)
		tasklet_hi_schedule(&phnat_ipi->smp_func_call_tsk);
}

void sch_smp_call(int is_thecpu, struct hnat_ipi_s *phnat_ipi, unsigned int cpu_num)
{
	if (is_thecpu == 1) {
		tasklet_hi_schedule(&phnat_ipi->smp_func_call_tsk);
	} else {
		smp_call_function_single(cpu_num, smp_func_call_from_extif, NULL, 0);
		phnat_ipi->time_rec = jiffies;
	}
}

int32_t hnat_ipi_extif_handler(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)(skb->data - ETH_HLEN);

	unsigned int cpu_num;
	unsigned int kickoff_ipi = 1;
	int is_thecpu = 0;
	struct hnat_ipi_s *phnat_ipi;
	struct hnat_ipi_stat *phnat_ipi_stat;

	dbg_var++;
	if (dbg_var == 20)
		pr_info("=== [FromExtIf]hnat_ipi_enable=%d, queue_thresh=%d, drop_pkt=%d ===\n",
			hnat_ipi_config->enable_from_extif,
						hnat_ipi_config->queue_thresh_from_extif,
						hnat_ipi_config->drop_pkt_from_extif);
	if (hnat_ipi_config->enable_from_extif == 1) {
		/* unsigned long delta; */
		/*unsigned long cur_jiffies = jiffies;*/
		if (((skb->protocol != htons(ETH_P_8021Q)) &&
		     (skb->protocol != htons(ETH_P_IP)) && (skb->protocol != htons(ETH_P_IPV6)) &&
			(skb->protocol != htons(ETH_P_PPP_SES)) && (skb->protocol != htons(ETH_P_PPP_DISC))) ||
			is_multicast_ether_addr(&eth->h_dest[0]))
			return 1;

		cpu_num = skb_get_rxhash_ipi(skb, HNAT_IPI_HASH_NORMAL | HNAT_IPI_HASH_FROM_EXTIF);
		if (debug_level >= 1)
			pr_info("%s: cpu_num =%d\n", __func__, cpu_num);
		phnat_ipi_stat = hnat_ipi_status[cpu_num];
		if (!phnat_ipi_stat)
			goto DISABLE_EXTIF_IPI;
		phnat_ipi = hnat_ipi_from_extif[cpu_num];
		if (!phnat_ipi)
			goto DISABLE_EXTIF_IPI;

		phnat_ipi_stat->smp_call_cnt_from_extif++;
		phnat_ipi->ipi_accum++;

		if (phnat_ipi->ipi_accum >= hnat_ipi_config->ipi_cnt_mod_from_extif) {
			kickoff_ipi = 1;
			phnat_ipi->ipi_accum = 0;
		} else {
			kickoff_ipi = 0;
		}

		if (cpu_num == smp_processor_id())
			is_thecpu = 1;
			/* return ppe_extif_rx_handler(skb); */

#if defined(HNAT_IPI_DQ)
		if (skb_queue_len(&phnat_ipi->skb_input_queue) > hnat_ipi_config->drop_pkt_from_extif) {
#elif defined(HNAT_IPI_RXQUEUE)
		if (atomic_read(&phnat_ipi->rx_queue_num) >= (hnat_ipi_config->drop_pkt_from_extif - 1)) {
#else
		if (skb_queue_len(&phnat_ipi->skb_ipi_queue) > hnat_ipi_config->drop_pkt_from_extif) {
#endif

			dev_kfree_skb_any(skb);
			phnat_ipi_stat->drop_pkt_num_from_extif++;
			if (atomic_read(&phnat_ipi_stat->cpu_status_from_extif) <= 0) {
				if (is_thecpu == 1) {
					tasklet_hi_schedule(&phnat_ipi->smp_func_call_tsk);
				} else {
					smp_call_function_single(cpu_num, smp_func_call_from_extif, NULL, 0);
					phnat_ipi->time_rec = jiffies;
				}
				goto drop_pkt;
				/*return 0;*/
				/* Drop packet */
			} else {
				if (atomic_read(&phnat_ipi_stat->cpu_status_from_extif) <= 0) {
					/* idle state */
#if (defined(HNAT_IPI_DQ) || defined(HNAT_IPI_RXQUEUE))
					spin_lock(&phnat_ipi->ipilock);
#endif
#if defined(HNAT_IPI_DQ)
					__skb_queue_tail(&phnat_ipi->skb_input_queue, skb);
#elif defined(HNAT_IPI_RXQUEUE)
					phnat_ipi->rx_queue[phnat_ipi->rx_queue_widx] = skb;
					phnat_ipi->rx_queue_widx = (phnat_ipi->rx_queue_widx + 1) % 1024;
					atomic_add(1, &phnat_ipi->rx_queue_num);
#else
					skb_queue_tail(&phnat_ipi->skb_ipi_queue, skb);
#endif
#if (defined(HNAT_IPI_DQ) || defined(HNAT_IPI_RXQUEUE))
					spin_unlock(&phnat_ipi->ipilock);
#endif
					if (kickoff_ipi == 1)
						sch_smp_call(is_thecpu, phnat_ipi, cpu_num);

				} else {
#if (defined(HNAT_IPI_DQ) || defined(HNAT_IPI_RXQUEUE))
					spin_lock(&phnat_ipi->ipilock);
#endif
#if defined(HNAT_IPI_DQ)
					__skb_queue_tail(&phnat_ipi->skb_input_queue, skb);
#elif defined(HNAT_IPI_RXQUEUE)
					phnat_ipi->rx_queue[phnat_ipi->rx_queue_widx] = skb;
					phnat_ipi->rx_queue_widx = (phnat_ipi->rx_queue_widx + 1) % 1024;
					atomic_add(1, &phnat_ipi->rx_queue_num);
#else
					skb_queue_tail(&phnat_ipi->skb_ipi_queue, skb);
#endif
#if (defined(HNAT_IPI_DQ) || defined(HNAT_IPI_RXQUEUE))
					spin_unlock(&phnat_ipi->ipilock);
#endif
				}
			}
			if (debug_level >= 1)
				pr_info("%s, return 0\n", __func__);

			goto drop_pkt;
			/*return 0;*/
		} else {
DISABLE_EXTIF_IPI:
			return ppe_extif_rx_handler(skb);
		}
drop_pkt:
		return 0;
}

int32_t hnat_ipi_force_cpu(struct sk_buff *skb)
{
	unsigned int cpu_num;
#if defined(CONFIG_RAETH_QDMA)
	struct foe_entry *entry = NULL;
#else
	/* struct foe_entry *entry = &PpeFoeBase[FOE_ENTRY_NUM(skb)]; */
	struct foe_entry *entry = &ppe_foe_base[FOE_ENTRY_NUM(skb)];
#endif
	unsigned int kickoff_ipi = 1;
	int is_thecpu = 0;

	dbg_var2++;
	if (dbg_var2 == 20)
		pr_info("=== [FromPPE]hnat_ipi_enable=%d, queue_thresh=%d, drop_pkt=%d ===\n",
			hnat_ipi_config->enable_from_ppehit,
					hnat_ipi_config->queue_thresh_from_ppehit,
					hnat_ipi_config->drop_pkt_from_ppehit);
	if (hnat_ipi_config->enable_from_ppehit == 1) {
		/*unsigned long cur_jiffies = jiffies;*/
		/* unsigned long delta = 0; */
		hnat_ipi_s *phnat_ipi;
		hnat_ipi_stat *phnat_ipi_stat;

		cpu_num = skb_get_rxhash_ipi(skb, HNAT_IPI_HASH_VTAG | HNAT_IPI_HASH_FROM_GMAC);
		if (debug_level >= 1)
			pr_info("%s: cpu_num =%d\n", __func__, cpu_num);
		phnat_ipi = hnat_ipi_from_ppehit[cpu_num];
		phnat_ipi_stat = hnat_ipi_status[cpu_num];
		if (!phnat_ipi_stat)
			goto DISABLE_PPEHIT_IPI;

		if (!phnat_ipi)
			goto DISABLE_PPEHIT_IPI;

		phnat_ipi_stat->smp_call_cnt_from_ppehit++;
		phnat_ipi->ipi_accum++;

		if (phnat_ipi->ipi_accum >= hnat_ipi_config->ipi_cnt_mod_from_ppehit) {
			kickoff_ipi = 1;
			phnat_ipi->ipi_accum = 0;
		} else {
			kickoff_ipi = 0;
		}

		if (cpu_num == smp_processor_id())
			is_thecpu = 1;
			/* return  hitbind_force_to_cpu_handler(skb, foe_entry); */
#if defined(HNAT_IPI_DQ)
		if (skb_queue_len(&phnat_ipi->skb_input_queue) > hnat_ipi_config->drop_pkt_from_ppehit) {
#elif defined(HNAT_IPI_RXQUEUE)
		if (atomic_read(&phnat_ipi->rx_queue_num) >= (hnat_ipi_config->drop_pkt_from_ppehit - 1)) {
#else
		if (skb_queue_len(&phnat_ipi->skb_ipi_queue) > hnat_ipi_config->drop_pkt_from_ppehit) {
#endif

			dev_kfree_skb_any(skb);
			phnat_ipi_stat->drop_pkt_num_from_ppehit++;
				if (atomic_read(&phnat_ipi_stat->cpu_status_from_ppehit) <= 0) {
					if (is_thecpu == 1)
						tasklet_hi_schedule(&phnat_ipi->smp_func_call_tsk);
					else
						smp_call_function_single(cpu_num, smp_func_call_from_ppehit, NULL, 0);
					phnat_ipi->time_rec = jiffies;
				}
			/*return 0;*/
			/* Drop packet */
		} else {
			if (atomic_read(&phnat_ipi_stat->cpu_status_from_ppehit) <= 0) {
#if (defined(HNAT_IPI_DQ) || defined(HNAT_IPI_RXQUEUE))
				spin_lock(&phnat_ipi->ipilock);
#endif
		      /* idle state */
#if defined(HNAT_IPI_DQ)
				__skb_queue_tail(&phnat_ipi->skb_input_queue, skb);
#elif defined(HNAT_IPI_RXQUEUE)
				phnat_ipi->rx_queue[phnat_ipi->rx_queue_widx] = skb;
				phnat_ipi->rx_queue_widx = (phnat_ipi->rx_queue_widx + 1) % 1024;
				atomic_add(1, &phnat_ipi->rx_queue_num);
#else
				skb_queue_tail(&phnat_ipi->skb_ipi_queue, skb);
#endif
#if (defined(HNAT_IPI_DQ) || defined(HNAT_IPI_RXQUEUE))
				spin_unlock(&phnat_ipi->ipilock);
#endif
				if (kickoff_ipi == 1) {
					if (is_thecpu == 1)
						tasklet_hi_schedule(&phnat_ipi->smp_func_call_tsk);
					else
						smp_call_function_single(cpu_num, smp_func_call_from_ppehit, NULL, 0);
					phnat_ipi->time_rec = jiffies;
				}
			} else {
#if (defined(HNAT_IPI_DQ) || defined(HNAT_IPI_RXQUEUE))
					spin_lock(&phnat_ipi->ipilock);
#endif
#if defined(HNAT_IPI_DQ)
					__skb_queue_tail(&phnat_ipi->skb_input_queue, skb);
#elif defined(HNAT_IPI_RXQUEUE)
					phnat_ipi->rx_queue[phnat_ipi->rx_queue_widx] = skb;
					phnat_ipi->rx_queue_widx = (phnat_ipi->rx_queue_widx + 1) % 1024;
					atomic_add(1, &phnat_ipi->rx_queue_num);
#else
					skb_queue_tail(&phnat_ipi->skb_ipi_queue, skb);
#endif
#if (defined(HNAT_IPI_DQ) || defined(HNAT_IPI_RXQUEUE))
					spin_unlock(&phnat_ipi->ipilock);
#endif
			}
		}
			return 0;
	} else {
DISABLE_PPEHIT_IPI:
			return hitbind_force_to_cpu_handler(skb, entry);
	}
}

void ipi_monitor_from_extif(unsigned long data)
{
	int i;
	unsigned long delta;
	unsigned long cur_time;

	if (hnat_ipi_config->enable_from_extif == 1) {
		hnat_ipi_s *phnat_ipi;
		hnat_ipi_stat *phnat_ipi_status;

		cur_time = jiffies;

		for (i = 0; i < num_possible_cpus(); i++) {
			phnat_ipi = hnat_ipi_from_extif[i];
			phnat_ipi_status = hnat_ipi_status[i];
#if defined(HNAT_IPI_DQ)
			if (((skb_queue_len(&phnat_ipi->skb_input_queue) > 0) ||
			     (skb_queue_len(&phnat_ipi->skb_process_queue) > 0)) &&
				(atomic_read(&phnat_ipi_status->cpu_status_from_extif) <= 0)) {
#elif defined(HNAT_IPI_RXQUEUE)
			spin_lock(&phnat_ipi->ipilock);
			if ((atomic_read(&phnat_ipi->rx_queue_num) > 0) &&
			    (atomic_read(&phnat_ipi_status->cpu_status_from_extif) <= 0)) {
#else
			if ((skb_queue_len(&phnat_ipi->skb_ipi_queue) > 0) &&
			    (atomic_read(&phnat_ipi_status->cpu_status_from_extif) <= 0)) {
#endif
				delta = cur_time - phnat_ipi->time_rec;
				if (delta > 1) {
					smp_call_function_single(i, smp_func_call_from_extif, NULL, 0);
					phnat_ipi->time_rec = jiffies;
				}
			}
#ifdef HNAT_IPI_RXQUEUE
			spin_unlock(&phnat_ipi->ipilock);
#endif
		}
		mod_timer(&ipi_monitor_timer_from_extif, jiffies + 1);
	}
}

void ipi_monitor_from_ppehit(unsigned long data)
{
	int i;
	unsigned long delta;
	unsigned long cur_time;

	if (hnat_ipi_config->enable_from_ppehit == 1) {
		hnat_ipi_s *phnat_ipi;
		hnat_ipi_stat *phnat_ipi_status;

		cur_time = jiffies;
		for (i = 0; i < num_possible_cpus(); i++) {
			phnat_ipi = hnat_ipi_from_ppehit[i];
			phnat_ipi_status = hnat_ipi_status[i];
#if defined(HNAT_IPI_DQ)
			if (((skb_queue_len(&phnat_ipi->skb_input_queue) > 0) ||
			     (skb_queue_len(&phnat_ipi->skb_process_queue) > 0)) &&
				(atomic_read(&phnat_ipi_status->cpu_status_from_ppehit) <= 0)) {
#elif defined(HNAT_IPI_RXQUEUE)
			spin_lock(&phnat_ipi->ipilock);
			if ((atomic_read(&phnat_ipi->rx_queue_num) > 0) &&
			    (atomic_read(&phnat_ipi_status->cpu_status_from_ppehit) <= 0)) {
#else
			if ((skb_queue_len(&phnat_ipi->skb_ipi_queue) > 0) &&
			    (atomic_read(&phnat_ipi_status->cpu_status_from_ppehit) <= 0)) {
#endif
				delta = cur_time - phnat_ipi->time_rec;
				if (delta > 1) {
					smp_call_function_single(i, smp_func_call_from_ppehit, NULL, 0);
					phnat_ipi->time_rec = jiffies;
				}
			}
#ifdef HNAT_IPI_RXQUEUE
			spin_unlock(&phnat_ipi->ipilock);
#endif
		}
	  mod_timer(&ipi_monitor_timer_from_ppehit, jiffies + 1);
	}
}

int hnat_ipi_init(void)
{
	int i;
	   /* pr_info("========= %s(%d)[%s]: init HNAT IPI [%d CPUs](%d) =========\n\n",*/
	   /*__func__, __LINE__,__TIME__,num_possible_cpus(),sizeof(hnat_ipi_s)); */
	pr_info("========= %s: init HNAT IPI [%d CPUs](%lu) =========\n\n", __func__,
		num_possible_cpus(), sizeof(hnat_ipi_s));
	  /* hnat_ipi_config = &hnat_ipi_config_ctx; */
/* hnat_ipi_from_extif[0] = kzalloc(sizeof(hnat_ipi_s)*num_possible_cpus(), GFP_ATOMIC); */
 /* hnat_ipi_from_ppehit[0] = kzalloc(sizeof(hnat_ipi_s)*num_possible_cpus(), GFP_ATOMIC); */
 /* hnat_ipi_status[0] = kzalloc(sizeof(hnat_ipi_stat)*num_possible_cpus(), GFP_ATOMIC); */

	hnat_ipi_from_extif[0] = kzalloc((sizeof(hnat_ipi_s) * 2 + sizeof(hnat_ipi_stat)) * num_possible_cpus() +
				sizeof(hnat_ipi_config), GFP_ATOMIC);
	hnat_ipi_from_ppehit[0] = ((hnat_ipi_s *)hnat_ipi_from_extif[0]) + sizeof(hnat_ipi_s) * num_possible_cpus();
	hnat_ipi_status[0] = ((hnat_ipi_stat *)hnat_ipi_from_ppehit[0]) + sizeof(hnat_ipi_s) * num_possible_cpus();
	hnat_ipi_config = ((hnat_ipi_cfg *)hnat_ipi_status[0]) + sizeof(hnat_ipi_stat) * num_possible_cpus();
	if ((!hnat_ipi_from_extif[0]) || (!hnat_ipi_from_ppehit[0]) ||
	    (!hnat_ipi_status[0]) || (!hnat_ipi_config)) {
		kfree(hnat_ipi_from_extif[0]);
/* if (hnat_ipi_from_ppehit[0]) */
  /* kfree(hnat_ipi_from_ppehit[0]); */
  /* if (hnat_ipi_status[0]) */
  /* kfree(hnat_ipi_status[0]); */
		pr_info("Hnat IPI allocation failed\n");
		return -1;
	}
	memset(hnat_ipi_config, 0, sizeof(hnat_ipi_cfg));
	for (i = 0; i < num_possible_cpus(); i++) {
		hnat_ipi_from_extif[i] = hnat_ipi_from_extif[0] + 1 * i;
		hnat_ipi_from_ppehit[i] = hnat_ipi_from_ppehit[0] + 1 * i;
		hnat_ipi_status[i] = hnat_ipi_status[0] + 1 * i;
	/* pr_info("hnat_ipi_from_extif[%d]=0x%x\n",i,hnat_ipi_from_extif[i]); */
	/* pr_info("hnat_ipi_from_ppehit[%d]=0x%x\n",i,hnat_ipi_from_ppehit[i]); */
	/* pr_info("hnat_ipi_status[%d]=0x%x\n",i,hnat_ipi_status[i]); */

#if (defined(HNAT_IPI_RXQUEUE) || defined(HNAT_IPI_DQ))
		spin_lock_init(&hnat_ipi_from_extif[i]->ipilock);
		spin_lock_init(&hnat_ipi_from_ppehit[i]->ipilock);
#endif
#if defined(HNAT_IPI_RXQUEUE)
		/*hnat_ipi_from_extif[i]->rx_queue = kmalloc(sizeof(struct sk_buff) * 1024, GFP_KERNEL);*/
		hnat_ipi_from_extif[i]->rx_queue = kmalloc(sizeof(*hnat_ipi_from_extif[i]->rx_queue), GFP_KERNEL);
		atomic_set(&hnat_ipi_from_extif[i]->rx_queue_num, 0);
		hnat_ipi_from_extif[i]->rx_queue_widx = 0;
		hnat_ipi_from_extif[i]->rx_queue_ridx = 0;

		/*hnat_ipi_from_ppehit[i]->rx_queue = kmalloc(sizeof(struct sk_buff) * 1024, GFP_KERNEL);*/
		hnat_ipi_from_ppehit[i]->rx_queue = kmalloc(sizeof(*hnat_ipi_from_ppehit[i]->rx_queue), GFP_KERNEL);
		atomic_set(&hnat_ipi_from_ppehit[i]->rx_queue_num, 0);
		hnat_ipi_from_ppehit[i]->rx_queue_widx = 0;
		hnat_ipi_from_ppehit[i]->rx_queue_ridx = 0;

#elif defined(HNAT_IPI_DQ)
		skb_queue_head_init(&hnat_ipi_from_extif[i]->skb_input_queue);
		skb_queue_head_init(&hnat_ipi_from_extif[i]->skb_process_queue);

		skb_queue_head_init(&hnat_ipi_from_ppehit[i]->skb_input_queue);
		skb_queue_head_init(&hnat_ipi_from_ppehit[i]->skb_process_queue);
#else
		skb_queue_head_init(&hnat_ipi_from_extif[i]->skb_ipi_queue);
		skb_queue_head_init(&hnat_ipi_from_ppehit[i]->skb_ipi_queue);
#endif
		atomic_set(&hnat_ipi_status[i]->cpu_status_from_extif, 0);
		hnat_ipi_status[i]->drop_pkt_num_from_extif = 0;
		hnat_ipi_status[i]->smp_call_cnt_from_extif = 0;
		tasklet_init(&hnat_ipi_from_extif[i]->smp_func_call_tsk, smp_func_call_BH_handler_from_extif, 0);

		atomic_set(&hnat_ipi_status[i]->cpu_status_from_ppehit, 0);
		hnat_ipi_status[i]->drop_pkt_num_from_ppehit = 0;
		hnat_ipi_status[i]->smp_call_cnt_from_ppehit = 0;
		tasklet_init(&hnat_ipi_from_ppehit[i]->smp_func_call_tsk, smp_func_call_BH_handler_from_ppehit, 0);
	}

	memset(ipidbg, 0, sizeof(ipidbg));
	memset(ipidbg2, 0, sizeof(ipidbg2));

	ipi_monitor_timer_from_extif.function = NULL;
	ipi_monitor_timer_from_ppehit.function = NULL;
	pr_info("========= %s(%d): init HNAT IPI =========\n\n", __func__, __LINE__);
	return 0;
}

int hnat_ipi_de_init(void)
{
	int i, j;
	struct sk_buff *skb_deq = NULL;
	unsigned int current_ipi_enable_from_extif = hnat_ipi_config->enable_from_extif;
	unsigned int current_ipi_enable_from_ppehit = hnat_ipi_config->enable_from_ppehit;
	struct hnat_ipi_s *phnat_ipi_from_extif;
	struct hnat_ipi_s *phnat_ipi_from_ppehit;
	struct hnat_ipi_stat *phnat_ipi_status;

	hnat_ipi_config->enable_from_extif = 0;
	hnat_ipi_config->enable_from_ppehit = 0;
	if (ipi_monitor_timer_from_extif.function)
		del_timer_sync(&ipi_monitor_timer_from_extif);
	if (ipi_monitor_timer_from_ppehit.function)
		del_timer_sync(&ipi_monitor_timer_from_ppehit);

	for (i = 0; i < num_possible_cpus(); i++) {
	/* int qlen; */
		phnat_ipi_from_extif = hnat_ipi_from_extif[i];
		phnat_ipi_from_ppehit = hnat_ipi_from_ppehit[i];
		phnat_ipi_status = hnat_ipi_status[i];

		if (current_ipi_enable_from_extif == 1) {
			while (1) {
				if (atomic_read(&phnat_ipi_status->cpu_status_from_extif) >= 1)
					break;
			}
		}

		if (current_ipi_enable_from_ppehit) {
			while (1) {
				if (atomic_read(&phnat_ipi_status->cpu_status_from_ppehit) >= 1)
					break;
			}
		}

		if (current_ipi_enable_from_extif == 1)
			tasklet_kill(&phnat_ipi_from_extif->smp_func_call_tsk);
		if (current_ipi_enable_from_ppehit == 1)
			tasklet_kill(&phnat_ipi_from_ppehit->smp_func_call_tsk);

#if defined(HNAT_IPI_DQ)
		for (j = 0; j < phnat_ipi_from_extif->skb_input_queue.qlen; j++) {
			skb_deq = skb_dequeue(&phnat_ipi_from_extif->skb_input_queue);
			if (skb_deq)
				dev_kfree_skb_any(skb_deq);
		}

		for (j = 0; j < phnat_ipi_from_ppehit->skb_input_queue.qlen; j++) {
			skb_deq = skb_dequeue(&phnat_ipi_from_ppehit->skb_input_queue);
			if (skb_deq)
				dev_kfree_skb_any(skb_deq);
			else
			break;
		}
		for (j = 0; j < phnat_ipi_from_extif->skb_process_queue.qlen; j++) {
			skb_deq = skb_dequeue(&phnat_ipi_from_extif->skb_process_queue);
			if (skb_deq)
				dev_kfree_skb_any(skb_deq);
		}
		for (j = 0; j < phnat_ipi_from_ppehit->skb_process_queue.qlen; j++) {
			skb_deq = skb_dequeue(&phnat_ipi_from_ppehit->skb_process_queue);
			if (skb_deq)
				dev_kfree_skb_any(skb_deq);
		}
#elif defined(HNAT_IPI_RXQUEUE)
		qlen = atomic_read(&phnat_ipi_from_extif->rx_queue_num);
		for (j = 0; j < qlen; j++) {
			skb_deq = phnat_ipi_from_extif->rx_queue[phnat_ipi_from_extif->rx_queue_ridx];
			if (skb_deq)
				dev_kfree_skb_any(skb_deq);
			phnat_ipi_from_extif->rx_queue[phnat_ipi_from_extif->rx_queue_ridx] = NULL;
			phnat_ipi_from_extif->rx_queue_ridx = (phnat_ipi_from_extif->rx_queue_ridx + 1) % 1024;
		}
		qlen = atomic_read(&phnat_ipi_from_ppehit->rx_queue_num);

		for (j = 0; j < qlen; j++) {
			skb_deq = phnat_ipi_from_ppehit->rx_queue[phnat_ipi_from_ppehit->rx_queue_ridx];
			if (skb_deq)
				dev_kfree_skb_any(skb_deq);
			phnat_ipi_from_ppehit->rx_queue[phnat_ipi_from_ppehit->rx_queue_ridx] = NULL;
			phnat_ipi_from_ppehit->rx_queue_ridx = (phnat_ipi_from_ppehit->rx_queue_ridx + 1) % 1024;
		}
		kfree(phnat_ipi_from_extif->rx_queue);
		kfree(phnat_ipi_from_ppehit->rx_queue);
#else
		qlen = skb_queue_len(&phnat_ipi_from_extif->skb_ipi_queue);
		for (j = 0; j < qlen; j++) {
			skb_deq = skb_dequeue(&phnat_ipi_from_extif->skb_ipi_queue);
			if (skb_deq)
				dev_kfree_skb_any(skb_deq);
			else
				break;
		}
		qlen = skb_queue_len(&phnat_ipi_from_ppehit->skb_ipi_queue);
		for (j = 0; j < qlen; j++) {
			skb_deq = skb_dequeue(&phnat_ipi_from_ppehit->skb_ipi_queue);
			if (skb_deq)
				dev_kfree_skb_any(skb_deq);
			else
				break;
		}
#endif
	}
	hnat_ipi_s *phnat_ipi = hnat_ipi_from_extif[0];

	/* hnat_ipi_stat* phnat_ipi_status = hnat_ipi_status[0]; */

	kfree(phnat_ipi);
/* phnat_ipi = hnat_ipi_from_ppehit[0]; */
/* if (phnat_ipi) */
/* kfree(phnat_ipi); */
/* if (phnat_ipi_status) */
/* kfree(phnat_ipi_status); */

	ipi_monitor_timer_from_extif.function = NULL;
	ipi_monitor_timer_from_ppehit.function = NULL;

	return 0;
}

int hnat_ipi_timer_setup(void)
{
	if ((hnat_ipi_config->enable_from_extif == 1) &&
	    (!ipi_monitor_timer_from_extif.function)) {
		init_timer(&ipi_monitor_timer_from_extif);
		ipi_monitor_timer_from_extif.function = ipi_monitor_from_extif;
		ipi_monitor_timer_from_extif.expires = jiffies + 1;
		add_timer(&ipi_monitor_timer_from_extif);
		return 0;
	}
	if ((hnat_ipi_config->enable_from_ppehit == 1) &&
	    (!ipi_monitor_timer_from_ppehit.function)) {
		init_timer(&ipi_monitor_timer_from_ppehit);
		ipi_monitor_timer_from_ppehit.function = ipi_monitor_from_ppehit;
		ipi_monitor_timer_from_ppehit.expires = jiffies + 1;
		add_timer(&ipi_monitor_timer_from_ppehit);
		return 0;
	}
	return 0;
}
