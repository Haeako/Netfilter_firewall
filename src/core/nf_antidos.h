/* SPDX-License-Identifier: GPL-2.0
 * nf_antidos/core/nf_antidos.h
 */
#ifndef NF_ANTIDOS_H
#define NF_ANTIDOS_H

#include "../plugins/rl_plugin.h"

#include <linux/hashtable.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include <linux/timer.h>
#include <linux/types.h>

/* -----------------------------------------------------------------------
 * Hash table size constants
 * ----------------------------------------------------------------------- */
#define BL_HASH_BITS 10
#define CC_HASH_BITS 10
#define RL_HASH_BITS 10

/* -----------------------------------------------------------------------
 * Data structures
 * ----------------------------------------------------------------------- */

/* Blacklist entry */
struct ban_entry {
	__be32            src_ip;
	unsigned long     expires;   /* jiffies khi hết ban */
	struct hlist_node hnode;
};

/* Whitelist entry */
struct whitelist_entry {
	__be32            ip;
	struct hlist_node hnode;
};

/*
 * Connection count entry — đếm số SYN từ mỗi IP trong cửa sổ thời gian.
 * count được reset bởi cleanup timer theo entry_ttl_sec.
 */
struct conn_entry {
	__be32            src_ip;
	atomic_t          count;      /* số SYN đã thấy */
	unsigned long     last_seen;  /* jiffies lần cuối thấy SYN */
	unsigned int      violations; /* lần vượt limit → auto-ban */
	struct hlist_node hnode;
};

/* -----------------------------------------------------------------------
 * Module parameters (defined in nf_antidos.c)
 * ----------------------------------------------------------------------- */
extern unsigned int max_conn_per_ip;
extern unsigned int ban_threshold;
extern unsigned int ban_ttl_sec;
extern unsigned int entry_ttl_sec;
extern unsigned int cleanup_sec;

/* -----------------------------------------------------------------------
 * Spinlocks (defined in nf_antidos.c)
 * Thứ tự acquire bắt buộc: conn_lock → ban_lock
 * rl_lock và plugin_list_lock dùng độc lập
 * ----------------------------------------------------------------------- */
extern spinlock_t ban_lock;
extern spinlock_t whitelist_lock;
extern spinlock_t conn_lock;
extern spinlock_t rl_lock;
extern spinlock_t plugin_list_lock;

/* -----------------------------------------------------------------------
 * Plugin registry (defined in nf_antidos.c)
 * ----------------------------------------------------------------------- */
extern struct list_head  plugin_list;
extern struct rl_plugin *active_plugin;

/* -----------------------------------------------------------------------
 * Statistics (defined in nf_antidos.c)
 * ----------------------------------------------------------------------- */
extern atomic64_t stat_accepted;
extern atomic64_t stat_dropped_bl;
extern atomic64_t stat_dropped_cc;
extern atomic64_t stat_dropped_rl;
extern atomic64_t stat_auto_bans;

/* -----------------------------------------------------------------------
 * Plugin registry API (exported by nf_antidos.c)
 * ----------------------------------------------------------------------- */


#endif /* NF_ANTIDOS_H */