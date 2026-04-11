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

/*
 * nf_conntrack.h cung cấp:
 *   - struct nf_conn
 *   - nf_ct_get()
 *   - enum ip_conntrack_info  (IP_CT_NEW, IP_CT_ESTABLISHED, ...)
 *
 * LƯU Ý: IP_CT_INVALID không tồn tại trong kernel 5.x.
 * Dùng ctinfo >= IP_CT_NUMBER để bắt packet không hợp lệ,
 * hoặc kiểm tra ct == NULL sau nf_ct_get().
 */
#include <net/netfilter/nf_conntrack.h>

/* -----------------------------------------------------------------------
 * Hash table size constants
 * ----------------------------------------------------------------------- */
#define BL_HASH_BITS  10
#define CC_HASH_BITS  10
#define RL_HASH_BITS  10

/* -----------------------------------------------------------------------
 * Data structures
 * ----------------------------------------------------------------------- */
struct ban_entry {
	__be32            src_ip;
	unsigned long     expires;   /* jiffies khi hết ban */
	struct hlist_node hnode;
};

struct whitelist_entry {
	__be32            ip;
	struct hlist_node hnode;
};

struct conn_entry {
	__be32            src_ip;
	atomic_t          count;       /* số SYN đang đếm */
	unsigned long     last_seen;
	unsigned int      violations;  /* số lần vi phạm → auto-ban */
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
 *
 * Thứ tự acquire bắt buộc để tránh deadlock:
 *   plugin_list_lock → conn_lock → ban_lock
 *   rl_lock: dùng độc lập, không giữ cùng lúc với các lock trên
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
 * Statistics counters (defined in nf_antidos.c)
 * ----------------------------------------------------------------------- */
extern atomic64_t stat_accepted;
extern atomic64_t stat_dropped_bl;
extern atomic64_t stat_dropped_invalid;
extern atomic64_t stat_dropped_cc;
extern atomic64_t stat_dropped_rl;
extern atomic64_t stat_auto_bans;

/*
 * === QUAN TRỌNG: Tại sao không có "extern" hashtable ở đây ===
 *
 * DEFINE_HASHTABLE(name, bits) mở rộng thành:
 *   struct hlist_head name[1 << bits]
 *
 * Các macro hash_init(), hash_for_each(), hash_for_each_safe()
 * đều gọi HASH_SIZE(name) → ARRAY_SIZE(name) → sizeof(name)/sizeof(name[0])
 *
 * sizeof() trên một mảng chỉ hoạt động khi compiler biết kích thước
 * mảng tại compile time (complete type). Nếu khai báo:
 *   extern struct hlist_head name[];   ← incomplete array type
 * thì sizeof() sẽ lỗi:
 *   "invalid application of sizeof to incomplete type"
 *
 * Giải pháp: DEFINE_HASHTABLE phải đặt trong nf_antidos.c và chỉ
 * được dùng trong file đó. Plugin không truy cập hashtable trực tiếp.
 */

/* -----------------------------------------------------------------------
 * Plugin registry API (implemented in nf_antidos.c, exported via
 * EXPORT_SYMBOL_GPL — dùng được từ plugin module khác)
 * ----------------------------------------------------------------------- */
int               rl_plugin_register(struct rl_plugin *p);
void              rl_plugin_unregister(struct rl_plugin *p);
int               rl_plugin_set_active(const char *name);
struct rl_plugin *rl_plugin_get_active(void);

#endif /* NF_ANTIDOS_H */