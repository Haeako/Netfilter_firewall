/* SPDX-License-Identifier: GPL-2.0
 * nf_antidos/core/nf_antidos.c
 */
#include "nf_antidos.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nf_antidos");
MODULE_DESCRIPTION("Anti-DoS Netfilter firewall — plugin rate-limit, conn limit, auto-ban");
MODULE_VERSION("1.0");

/* -----------------------------------------------------------------------
 * Module parameters
 * ----------------------------------------------------------------------- */
unsigned int max_conn_per_ip  = 20;
unsigned int ban_threshold    = 5;
unsigned int ban_ttl_sec      = 300;
unsigned int entry_ttl_sec    = 120;
unsigned int cleanup_sec      = 30;

module_param(max_conn_per_ip,  uint, 0644);
module_param(ban_threshold,    uint, 0644);
module_param(ban_ttl_sec,      uint, 0644);
module_param(entry_ttl_sec,    uint, 0644);
module_param(cleanup_sec,      uint, 0644);

MODULE_PARM_DESC(max_conn_per_ip, "Max concurrent SYN per IP");
MODULE_PARM_DESC(ban_threshold,   "Violations before auto-ban");
MODULE_PARM_DESC(ban_ttl_sec,     "Ban duration in seconds");
MODULE_PARM_DESC(entry_ttl_sec,   "Idle entry TTL in seconds");
MODULE_PARM_DESC(cleanup_sec,     "Cleanup timer interval in seconds");

/* -----------------------------------------------------------------------
 * Hash tables
 *
 * PHẢI đặt DEFINE_HASHTABLE ở đây (cùng TU với code dùng chúng).
 * Không export ra header vì extern array[] là incomplete type và sẽ khiến
 * ARRAY_SIZE() / HASH_SIZE() lỗi compile.
 * ----------------------------------------------------------------------- */
static DEFINE_HASHTABLE(ban_table,       BL_HASH_BITS);
static DEFINE_HASHTABLE(whitelist_table, BL_HASH_BITS);
static DEFINE_HASHTABLE(conn_table,      CC_HASH_BITS);
static DEFINE_HASHTABLE(rl_table,        RL_HASH_BITS);

/* -----------------------------------------------------------------------
 * Spinlocks
 * Thứ tự acquire: plugin_list_lock → conn_lock → ban_lock
 *                 rl_lock dùng độc lập
 * ----------------------------------------------------------------------- */
DEFINE_SPINLOCK(ban_lock);
DEFINE_SPINLOCK(whitelist_lock);
DEFINE_SPINLOCK(conn_lock);
DEFINE_SPINLOCK(rl_lock);
DEFINE_SPINLOCK(plugin_list_lock);

/* -----------------------------------------------------------------------
 * Plugin registry
 * ----------------------------------------------------------------------- */
LIST_HEAD(plugin_list);
struct rl_plugin *active_plugin;

/* -----------------------------------------------------------------------
 * Statistics
 * ----------------------------------------------------------------------- */
atomic64_t stat_accepted        = ATOMIC64_INIT(0);
atomic64_t stat_dropped_bl      = ATOMIC64_INIT(0);
atomic64_t stat_dropped_invalid = ATOMIC64_INIT(0);
atomic64_t stat_dropped_cc      = ATOMIC64_INIT(0);
atomic64_t stat_dropped_rl      = ATOMIC64_INIT(0);
atomic64_t stat_auto_bans       = ATOMIC64_INIT(0);

/* -----------------------------------------------------------------------
 * Helpers: blacklist
 * Caller phải giữ ban_lock.
 * ----------------------------------------------------------------------- */
static bool bl_is_banned(__be32 ip)
{
	struct ban_entry  *e;
	struct hlist_node *tmp;
	unsigned long      now = jiffies;

	hash_for_each_possible_safe(ban_table, e, tmp, hnode, (u32)ip) {
		if (e->src_ip != ip)
			continue;
		if (time_before(now, e->expires))
			return true;
		/* TTL hết — xóa luôn */
		hash_del(&e->hnode);
		kfree(e);
		return false;
	}
	return false;
}

static void bl_ban_ip(__be32 ip)
{
	struct ban_entry *e;

	hash_for_each_possible(ban_table, e, hnode, (u32)ip) {
		if (e->src_ip == ip) {
			e->expires = jiffies + ban_ttl_sec * HZ;
			return;
		}
	}
	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (!e)
		return;
	e->src_ip  = ip;
	e->expires = jiffies + ban_ttl_sec * HZ;
	hash_add(ban_table, &e->hnode, (u32)ip);
	atomic64_inc(&stat_auto_bans);
	pr_info_ratelimited("nf_antidos: auto-ban %pI4 for %us\n",
			    &ip, ban_ttl_sec);
}

/* -----------------------------------------------------------------------
 * Helpers: whitelist
 * ----------------------------------------------------------------------- */
static bool wl_is_whitelisted(__be32 ip)
{
	struct whitelist_entry *e;
	bool found = false;

	spin_lock_bh(&whitelist_lock);
	hash_for_each_possible(whitelist_table, e, hnode, (u32)ip) {
		if (e->ip == ip) {
			found = true;
			break;
		}
	}
	spin_unlock_bh(&whitelist_lock);
	return found;
}

static void wl_add_ip(__be32 ip)
{
	struct whitelist_entry *e;

	spin_lock_bh(&whitelist_lock);
	hash_for_each_possible(whitelist_table, e, hnode, (u32)ip) {
		if (e->ip == ip) {
			spin_unlock_bh(&whitelist_lock);
			return;
		}
	}
	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (e) {
		e->ip = ip;
		hash_add(whitelist_table, &e->hnode, (u32)ip);
	}
	spin_unlock_bh(&whitelist_lock);
}

static void wl_del_ip(__be32 ip)
{
	struct whitelist_entry *e;
	struct hlist_node      *tmp;

	spin_lock_bh(&whitelist_lock);
	hash_for_each_possible_safe(whitelist_table, e, tmp, hnode, (u32)ip) {
		if (e->ip == ip) {
			hash_del(&e->hnode);
			kfree(e);
		}
	}
	spin_unlock_bh(&whitelist_lock);
}

/* -----------------------------------------------------------------------
 * Helpers: connection count
 * Caller phải giữ conn_lock.
 * ----------------------------------------------------------------------- */
static struct conn_entry *cc_get_or_create(__be32 ip)
{
	struct conn_entry *e;

	hash_for_each_possible(conn_table, e, hnode, (u32)ip) {
		if (e->src_ip == ip) {
			e->last_seen = jiffies;
			return e;
		}
	}
	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (!e)
		return NULL;
	e->src_ip     = ip;
	e->last_seen  = jiffies;
	e->violations = 0;
	atomic_set(&e->count, 0);
	hash_add(conn_table, &e->hnode, (u32)ip);
	return e;
}

/* -----------------------------------------------------------------------
 * Helpers: rate-limit entry
 * Caller phải giữ rl_lock.
 * ----------------------------------------------------------------------- */
static struct rl_entry *rl_get_or_create(__be32 ip, struct rl_plugin *plugin)
{
	struct rl_entry *e;

	hash_for_each_possible(rl_table, e, hnode, (u32)ip) {
		if (e->src_ip == ip) {
			e->last_seen = jiffies;
			return e;
		}
	}
	e = kmalloc(plugin->entry_size, GFP_ATOMIC);
	if (!e)
		return NULL;
	e->src_ip    = ip;
	e->last_seen = jiffies;
	hash_add(rl_table, &e->hnode, (u32)ip);
	plugin->init_entry(e);
	return e;
}

/* -----------------------------------------------------------------------
 * trigger_violation — tăng vi phạm và auto-ban nếu vượt ngưỡng.
 * Không được giữ bất kỳ lock nào khi gọi hàm này.
 * ----------------------------------------------------------------------- */
static void trigger_violation(__be32 src)
{
	struct conn_entry *cc;

	spin_lock_bh(&conn_lock);
	cc = cc_get_or_create(src);
	if (cc) {
		cc->violations++;
		if (cc->violations >= ban_threshold) {
			cc->violations = 0;
			spin_lock_bh(&ban_lock);
			bl_ban_ip(src);
			spin_unlock_bh(&ban_lock);
		}
	}
	spin_unlock_bh(&conn_lock);
}

/* -----------------------------------------------------------------------
 * Netfilter hook
 * ----------------------------------------------------------------------- */
static unsigned int antidos_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct iphdr           *iph;
	struct nf_conn         *ct;
	enum ip_conntrack_info  ctinfo;
	struct conn_entry      *cc;
	struct rl_entry        *re;
	struct rl_plugin       *plugin;
	__be32                  src;

	if (!skb)
		return NF_ACCEPT;
	if (skb->dev && (skb->dev->flags & IFF_LOOPBACK))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph)
		return NF_ACCEPT;

	src = iph->saddr;

	/* --- Whitelist --- */
	if (wl_is_whitelisted(src))
		return NF_ACCEPT;

	/* --- Blacklist --- */
	spin_lock_bh(&ban_lock);
	if (bl_is_banned(src)) {
		spin_unlock_bh(&ban_lock);
		atomic64_inc(&stat_dropped_bl);
		return NF_DROP;
	}
	spin_unlock_bh(&ban_lock);

	/*
	 * --- Conntrack ---
	 * nf_ct_get() trả về NULL nếu packet không có conntrack entry
	 * (ví dụ: NOTRACK). Chấp nhận những packet này.
	 *
	 * IP_CT_INVALID không tồn tại trong kernel 5.x.
	 * Packet không hợp lệ sẽ có ct == NULL hoặc ctinfo >= IP_CT_NUMBER.
	 */
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return NF_ACCEPT;

	if (ctinfo >= IP_CT_NUMBER) {
		/* Trạng thái conntrack không hợp lệ */
		atomic64_inc(&stat_dropped_invalid);
		return NF_DROP;
	}

	/* ESTABLISHED / RELATED: fast path */
	if (ctinfo == IP_CT_ESTABLISHED ||
	    ctinfo == IP_CT_ESTABLISHED_REPLY ||
	    ctinfo == IP_CT_RELATED ||
	    ctinfo == IP_CT_RELATED_REPLY) {
		atomic64_inc(&stat_accepted);
		return NF_ACCEPT;
	}

	/* --- Từ đây: NEW connection --- */

	/* --- Connection count limit (chỉ TCP SYN) --- */
	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *th = tcp_hdr(skb);

		if (th && th->syn && !th->ack) {
			spin_lock_bh(&conn_lock);
			cc = cc_get_or_create(src);
			if (cc && atomic_read(&cc->count) >= (int)max_conn_per_ip) {
				spin_unlock_bh(&conn_lock);
				trigger_violation(src);
				atomic64_inc(&stat_dropped_cc);
				return NF_DROP;
			}
			if (cc)
				atomic_inc(&cc->count);
			spin_unlock_bh(&conn_lock);
		}
	}

	/* --- Rate-limit plugin --- */
	spin_lock_bh(&plugin_list_lock);
	plugin = active_plugin;
	spin_unlock_bh(&plugin_list_lock);

	if (plugin) {
		bool exceeded = false;

		spin_lock_bh(&rl_lock);
		re = rl_get_or_create(src, plugin);
		if (re && !plugin->check(re))
			exceeded = true;
		spin_unlock_bh(&rl_lock);

		if (exceeded) {
			trigger_violation(src);
			atomic64_inc(&stat_dropped_rl);
			return NF_DROP;
		}
	}

	atomic64_inc(&stat_accepted);
	return NF_ACCEPT;
}

/* -----------------------------------------------------------------------
 * Cleanup timer
 * ----------------------------------------------------------------------- */
static struct timer_list cleanup_timer;

static void do_cleanup(struct timer_list *t)
{
	unsigned long      ttl = entry_ttl_sec * HZ;
	unsigned long      now = jiffies;
	struct hlist_node *tmp;
	int                bkt;

	spin_lock_bh(&conn_lock);
	{
		struct conn_entry *e;
		hash_for_each_safe(conn_table, bkt, tmp, e, hnode) {
			if (time_after(now, e->last_seen + ttl)) {
				hash_del(&e->hnode);
				kfree(e);
			}
		}
	}
	spin_unlock_bh(&conn_lock);

	spin_lock_bh(&rl_lock);
	{
		struct rl_entry *e;
		hash_for_each_safe(rl_table, bkt, tmp, e, hnode) {
			if (time_after(now, e->last_seen + ttl)) {
				hash_del(&e->hnode);
				kfree(e);
			}
		}
	}
	spin_unlock_bh(&rl_lock);

	spin_lock_bh(&ban_lock);
	{
		struct ban_entry *e;
		hash_for_each_safe(ban_table, bkt, tmp, e, hnode) {
			if (time_after(now, e->expires)) {
				hash_del(&e->hnode);
				kfree(e);
			}
		}
	}
	spin_unlock_bh(&ban_lock);

	mod_timer(&cleanup_timer, jiffies + cleanup_sec * HZ);
}

/* -----------------------------------------------------------------------
 * /proc interface
 * ----------------------------------------------------------------------- */
static struct proc_dir_entry *proc_dir;

static ssize_t proc_plugin_write(struct file *f, const char __user *buf,
				 size_t len, loff_t *off)
{
	char name[64] = {};

	if (len >= sizeof(name))
		return -EINVAL;
	if (copy_from_user(name, buf, len))
		return -EFAULT;
	name[strcspn(name, "\n")] = '\0';

	if (rl_plugin_set_active(name) < 0) {
		pr_warn("nf_antidos: unknown plugin '%s'\n", name);
		return -ENOENT;
	}
	return len;
}

static int proc_plugin_show(struct seq_file *m, void *v)
{
	struct rl_plugin *p;

	spin_lock(&plugin_list_lock);
	seq_printf(m, "active: %s\navailable:",
		   active_plugin ? active_plugin->name : "(none)");
	list_for_each_entry(p, &plugin_list, list)
		seq_printf(m, " %s", p->name);
	seq_putc(m, '\n');
	spin_unlock(&plugin_list_lock);
	return 0;
}

static int proc_plugin_open(struct inode *i, struct file *f)
{
	return single_open(f, proc_plugin_show, NULL);
}

static const struct proc_ops proc_plugin_ops = {
	.proc_open    = proc_plugin_open,
	.proc_read    = seq_read,
	.proc_write   = proc_plugin_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int proc_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		   "accepted:      %lld\n"
		   "drop_bl:       %lld\n"
		   "drop_invalid:  %lld\n"
		   "drop_conn:     %lld\n"
		   "drop_rl:       %lld\n"
		   "auto_bans:     %lld\n",
		   atomic64_read(&stat_accepted),
		   atomic64_read(&stat_dropped_bl),
		   atomic64_read(&stat_dropped_invalid),
		   atomic64_read(&stat_dropped_cc),
		   atomic64_read(&stat_dropped_rl),
		   atomic64_read(&stat_auto_bans));
	return 0;
}

static int proc_stats_open(struct inode *i, struct file *f)
{
	return single_open(f, proc_stats_show, NULL);
}

static const struct proc_ops proc_stats_ops = {
	.proc_open    = proc_stats_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int proc_banned_show(struct seq_file *m, void *v)
{
	struct ban_entry *e;
	unsigned long     now = jiffies;
	int               bkt;

	spin_lock_bh(&ban_lock);
	hash_for_each(ban_table, bkt, e, hnode) {
		long rem = (long)(e->expires - now) / HZ;

		if (rem > 0)
			seq_printf(m, "%pI4  ttl=%lds\n", &e->src_ip, rem);
	}
	spin_unlock_bh(&ban_lock);
	return 0;
}

static int proc_banned_open(struct inode *i, struct file *f)
{
	return single_open(f, proc_banned_show, NULL);
}

static const struct proc_ops proc_banned_ops = {
	.proc_open    = proc_banned_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int proc_whitelist_show(struct seq_file *m, void *v)
{
	struct whitelist_entry *e;
	int bkt;

	spin_lock_bh(&whitelist_lock);
	hash_for_each(whitelist_table, bkt, e, hnode)
		seq_printf(m, "%pI4\n", &e->ip);
	spin_unlock_bh(&whitelist_lock);
	return 0;
}

static ssize_t proc_whitelist_write(struct file *f, const char __user *buf,
				    size_t len, loff_t *off)
{
	char   cmd[64]    = {};
	char   ip_str[32] = {};
	__be32 ip;

	if (len >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;

	if (sscanf(cmd, "add %31s", ip_str) == 1) {
		ip = in_aton(ip_str);
		wl_add_ip(ip);
	} else if (sscanf(cmd, "del %31s", ip_str) == 1) {
		ip = in_aton(ip_str);
		wl_del_ip(ip);
	} else {
		return -EINVAL;
	}
	return len;
}

static int proc_whitelist_open(struct inode *i, struct file *f)
{
	return single_open(f, proc_whitelist_show, NULL);
}

static const struct proc_ops proc_whitelist_ops = {
	.proc_open    = proc_whitelist_open,
	.proc_read    = seq_read,
	.proc_write   = proc_whitelist_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* -----------------------------------------------------------------------
 * Netfilter ops
 * ----------------------------------------------------------------------- */
static struct nf_hook_ops nf_ops = {
	.hook     = antidos_hook,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_CONNTRACK + 10,
};

/* -----------------------------------------------------------------------
 * Module init / exit
 * ----------------------------------------------------------------------- */
static int __init antidos_init(void)
{
	int ret;

	/*
	 * hash_init() dùng HASH_SIZE() → ARRAY_SIZE() → sizeof(array).
	 * Hoạt động đúng vì ban_table/conn_table/... được DEFINE_HASHTABLE
	 * ngay trong file này (complete type).
	 */
	hash_init(ban_table);
	hash_init(conn_table);
	hash_init(rl_table);
	hash_init(whitelist_table);

	ret = nf_register_net_hook(&init_net, &nf_ops);
	if (ret) {
		pr_err("nf_antidos: hook register failed (%d)\n", ret);
		return ret;
	}

	timer_setup(&cleanup_timer, do_cleanup, 0);
	mod_timer(&cleanup_timer, jiffies + cleanup_sec * HZ);

	proc_dir = proc_mkdir("nf_antidos", NULL);
	if (proc_dir) {
		proc_create("plugin",    0644, proc_dir, &proc_plugin_ops);
		proc_create("stats",     0444, proc_dir, &proc_stats_ops);
		proc_create("banned",    0444, proc_dir, &proc_banned_ops);
		proc_create("whitelist", 0644, proc_dir, &proc_whitelist_ops);
	}

	pr_info("nf_antidos: loaded — max_conn=%u ban_thresh=%u ban_ttl=%us\n",
		max_conn_per_ip, ban_threshold, ban_ttl_sec);
	return 0;
}

static void __exit antidos_exit(void)
{
	struct hlist_node *tmp;
	int bkt;

	nf_unregister_net_hook(&init_net, &nf_ops);
	del_timer_sync(&cleanup_timer);

	if (proc_dir) {
		remove_proc_entry("plugin",     proc_dir);
		remove_proc_entry("stats",      proc_dir);
		remove_proc_entry("banned",     proc_dir);
		remove_proc_entry("whitelist",  proc_dir);
		remove_proc_entry("nf_antidos", NULL);
	}

	spin_lock_bh(&whitelist_lock);
	{
		struct whitelist_entry *e;
		hash_for_each_safe(whitelist_table, bkt, tmp, e, hnode) {
			hash_del(&e->hnode);
			kfree(e);
		}
	}
	spin_unlock_bh(&whitelist_lock);

	spin_lock_bh(&ban_lock);
	{
		struct ban_entry *e;
		hash_for_each_safe(ban_table, bkt, tmp, e, hnode) {
			hash_del(&e->hnode);
			kfree(e);
		}
	}
	spin_unlock_bh(&ban_lock);

	spin_lock_bh(&conn_lock);
	{
		struct conn_entry *e;
		hash_for_each_safe(conn_table, bkt, tmp, e, hnode) {
			hash_del(&e->hnode);
			kfree(e);
		}
	}
	spin_unlock_bh(&conn_lock);

	spin_lock_bh(&rl_lock);
	{
		struct rl_entry *e;
		hash_for_each_safe(rl_table, bkt, tmp, e, hnode) {
			hash_del(&e->hnode);
			kfree(e);
		}
	}
	spin_unlock_bh(&rl_lock);

	pr_info("nf_antidos: unloaded. accepted=%lld dropped=%lld\n",
		atomic64_read(&stat_accepted),
		atomic64_read(&stat_dropped_bl)      +
		atomic64_read(&stat_dropped_invalid) +
		atomic64_read(&stat_dropped_cc)      +
		atomic64_read(&stat_dropped_rl));
}

module_init(antidos_init);
module_exit(antidos_exit);

/* -----------------------------------------------------------------------
 * Plugin registry API
 * ----------------------------------------------------------------------- */
int rl_plugin_register(struct rl_plugin *p)
{
	spin_lock(&plugin_list_lock);
	list_add(&p->list, &plugin_list);
	if (!active_plugin)
		active_plugin = p;
	spin_unlock(&plugin_list_lock);
	pr_info("nf_antidos: plugin '%s' registered\n", p->name);
	return 0;
}
EXPORT_SYMBOL_GPL(rl_plugin_register);

void rl_plugin_unregister(struct rl_plugin *p)
{
	spin_lock(&plugin_list_lock);
	list_del(&p->list);
	if (active_plugin == p)
		active_plugin = list_empty(&plugin_list)
			? NULL
			: list_first_entry(&plugin_list, struct rl_plugin, list);
	spin_unlock(&plugin_list_lock);
	pr_info("nf_antidos: plugin '%s' unregistered\n", p->name);
}
EXPORT_SYMBOL_GPL(rl_plugin_unregister);

int rl_plugin_set_active(const char *name)
{
	struct rl_plugin *p;

	spin_lock(&plugin_list_lock);
	list_for_each_entry(p, &plugin_list, list) {
		if (strcmp(p->name, name) == 0) {
			active_plugin = p;
			spin_unlock(&plugin_list_lock);
			pr_info("nf_antidos: active plugin → '%s'\n", name);
			return 0;
		}
	}
	spin_unlock(&plugin_list_lock);
	return -ENOENT;
}
EXPORT_SYMBOL_GPL(rl_plugin_set_active);

struct rl_plugin *rl_plugin_get_active(void)
{
	return active_plugin;
}
EXPORT_SYMBOL_GPL(rl_plugin_get_active);