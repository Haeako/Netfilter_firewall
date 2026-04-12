/* SPDX-License-Identifier: GPL-2.0
 * nf_antidos/core/nf_antidos.c
 *
 * Stateless Anti-DoS Netfilter module.
 *
 * Chỉ xét TCP SYN packet (syn=1, ack=0):
 *   1. Whitelist  → NF_ACCEPT ngay
 *   2. Blacklist  → NF_DROP ngay
 *   3. Conn limit → đếm SYN per IP, drop nếu vượt max_conn_per_ip
 *   4. Rate limit → plugin (Token Bucket / Sliding Window / ...)
 *   5. Mọi packet khác (ACK, data, ...) → NF_ACCEPT, không xử lý
 *
 * Hook priority NF_IP_PRI_FIRST (-300):
 *   - Chạy trước conntrack → không cần iptables rule phụ
 *   - Không phụ thuộc nf_conntrack subsystem
 *
 * Trade-off stateless:
 *   - conn_entry.count chỉ tăng, không giảm khi connection kết thúc
 *   - Khi count >= max_conn_per_ip: KHÔNG tăng thêm (clamped tại max)
 *     → tránh integer overflow / wrap-around về 0
 *   - Cleanup timer xóa entry idle > entry_ttl_sec → count reset về 0
 */
#include "nf_antidos.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nf_antidos");
MODULE_DESCRIPTION("Anti-DoS Netfilter firewall — stateless SYN filter");
MODULE_VERSION("1.0");

/* -----------------------------------------------------------------------
 * Module parameters
 * ----------------------------------------------------------------------- */
unsigned int max_conn_per_ip = 20;
unsigned int ban_threshold   = 5;
unsigned int ban_ttl_sec     = 300;
unsigned int entry_ttl_sec   = 120;
unsigned int cleanup_sec     = 30;

module_param(max_conn_per_ip, uint, 0644);
module_param(ban_threshold,   uint, 0644);
module_param(ban_ttl_sec,     uint, 0644);
module_param(entry_ttl_sec,   uint, 0644);
module_param(cleanup_sec,     uint, 0644);

MODULE_PARM_DESC(max_conn_per_ip, "Max SYN count per IP trong entry_ttl_sec");
MODULE_PARM_DESC(ban_threshold,   "Violations trước khi auto-ban");
MODULE_PARM_DESC(ban_ttl_sec,     "Thời gian ban (giây)");
MODULE_PARM_DESC(entry_ttl_sec,   "Thời gian idle trước khi xóa entry (giây)");
MODULE_PARM_DESC(cleanup_sec,     "Chu kỳ cleanup timer (giây)");

/* -----------------------------------------------------------------------
 * Hash tables
 *
 * PHẢI định nghĩa trong cùng file với code dùng chúng.
 * Không export extern vì ARRAY_SIZE() cần complete type tại compile time.
 * ----------------------------------------------------------------------- */
static DEFINE_HASHTABLE(ban_table,       BL_HASH_BITS);
static DEFINE_HASHTABLE(whitelist_table, BL_HASH_BITS);
static DEFINE_HASHTABLE(conn_table,      CC_HASH_BITS);
static DEFINE_HASHTABLE(rl_table,        RL_HASH_BITS);

/* -----------------------------------------------------------------------
 * Spinlocks
 * Thứ tự acquire bắt buộc: conn_lock → ban_lock
 * rl_lock và plugin_list_lock dùng độc lập, không giữ cùng lúc
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
atomic64_t stat_accepted   = ATOMIC64_INIT(0);
atomic64_t stat_dropped_bl = ATOMIC64_INIT(0);
atomic64_t stat_dropped_cc = ATOMIC64_INIT(0);
atomic64_t stat_dropped_rl = ATOMIC64_INIT(0);
atomic64_t stat_auto_bans  = ATOMIC64_INIT(0);

/* =======================================================================
 * HELPERS: BLACKLIST
 * Caller phải giữ ban_lock.
 * ======================================================================= */
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
		/* Hết TTL → xóa luôn */
		hash_del(&e->hnode);
		kfree(e);
		return false;
	}
	return false;
}

static void bl_ban_ip(__be32 ip)
{
	struct ban_entry *e;

	/* Cập nhật nếu đã có */
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

/* Xóa IP khỏi blacklist thủ công. Caller phải giữ ban_lock. */
static void bl_unban_ip(__be32 ip)
{
	struct ban_entry  *e;
	struct hlist_node *tmp;

	hash_for_each_possible_safe(ban_table, e, tmp, hnode, (u32)ip) {
		if (e->src_ip == ip) {
			hash_del(&e->hnode);
			kfree(e);
			pr_info("nf_antidos: manual unban %pI4\n", &ip);
			return;
		}
	}
}

/* =======================================================================
 * HELPERS: WHITELIST
 * ======================================================================= */
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
	/* Kiểm tra trùng */
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

/* =======================================================================
 * HELPERS: CONNECTION COUNT
 * Caller phải giữ conn_lock.
 * ======================================================================= */
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

/* =======================================================================
 * HELPERS: RATE-LIMIT ENTRY
 * Caller phải giữ rl_lock.
 * ======================================================================= */
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

/* =======================================================================
 * HELPERS: TRIGGER VIOLATION + AUTO-BAN
 *
 * Không được giữ bất kỳ lock nào khi gọi hàm này.
 * Thứ tự lock bên trong: conn_lock → ban_lock
 * ======================================================================= */
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

/* =======================================================================
 * NETFILTER HOOK
 *
 * Chỉ xử lý TCP SYN (syn=1, ack=0).
 * Mọi packet khác → NF_ACCEPT ngay sau khi qua whitelist/blacklist.
 *
 * Parse TCP header thủ công từ iph->ihl thay vì tcp_hdr() vì
 * skb->transport_header có thể chưa được set ở NF_IP_PRI_FIRST.
 * ======================================================================= */
static unsigned int antidos_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct iphdr      *iph;
	struct tcphdr     *th;
	struct conn_entry *cc;
	struct rl_entry   *re;
	struct rl_plugin  *plugin;
	__be32             src;
	unsigned int       ip_hlen;

	/* --- Sanity checks --- */
	if (!skb)
		return NF_ACCEPT;

	/* Bỏ qua loopback */
	if (skb->dev && (skb->dev->flags & IFF_LOOPBACK))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph)
		return NF_ACCEPT;

	/* Chỉ IPv4 unicast */
	if (ipv4_is_multicast(iph->daddr) || ipv4_is_lbcast(iph->daddr))
		return NF_ACCEPT;

	src = iph->saddr;

	/* --- Whitelist: fast path --- */
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

	/* --- Chỉ xử lý TCP SYN --- */
	if (iph->protocol != IPPROTO_TCP) {
		atomic64_inc(&stat_accepted);
		return NF_ACCEPT;
	}

	ip_hlen = iph->ihl * 4;

	/* Kiểm tra skb đủ dài để đọc TCP header */
	if (skb->len < ip_hlen + sizeof(struct tcphdr)) {
		atomic64_inc(&stat_accepted);
		return NF_ACCEPT;
	}

	th = (struct tcphdr *)((u8 *)iph + ip_hlen);

	/* Không phải SYN → không cần rate-limit, cho qua */
	if (!th->syn || th->ack) {
		atomic64_inc(&stat_accepted);
		return NF_ACCEPT;
	}

	/* ================================================================
	 * Từ đây: TCP SYN thuần (new connection attempt)
	 * ================================================================ */

	/* --- Layer 1: Connection count limit ---
	 *
	 * Đếm số SYN từ IP này trong cửa sổ entry_ttl_sec.
	 * count không giảm khi connection kết thúc (stateless trade-off),
	 * nhưng cleanup timer sẽ xóa entry idle và reset count về 0.
	 *
	 * Dùng atomic_inc_return() + clamp để tránh integer overflow:
	 * nếu count đã >= max thì không tăng thêm (giữ nguyên ở max),
	 * tránh wrap-around về 0 khi attacker gửi 2^31 SYN.
	 */
	spin_lock_bh(&conn_lock);
	cc = cc_get_or_create(src);
	if (cc) {
		int cur = atomic_read(&cc->count);

		if (cur >= (int)max_conn_per_ip) {
			/* Giữ nguyên ở max, không tăng thêm */
			spin_unlock_bh(&conn_lock);
			trigger_violation(src);
			atomic64_inc(&stat_dropped_cc);
			return NF_DROP;
		}
		atomic_inc(&cc->count);  /* tăng chỉ khi còn dưới max */
	}
	spin_unlock_bh(&conn_lock);

	/* --- Layer 2: Rate-limit plugin --- */
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

/* =======================================================================
 * CLEANUP TIMER
 *
 * Chạy mỗi cleanup_sec giây, xóa các entry idle quá entry_ttl_sec.
 * Khi conn_entry bị xóa, count về 0 → IP đó được "tha" nếu không flood.
 * ======================================================================= */
static struct timer_list cleanup_timer;

static void do_cleanup(struct timer_list *t)
{
	unsigned long      ttl = entry_ttl_sec * HZ;
	unsigned long      now = jiffies;
	struct hlist_node *tmp;
	int                bkt;

	/* Xóa conn_entry idle */
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

	/* Xóa rl_entry idle */
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

	/* Xóa ban_entry hết hạn */
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

/* =======================================================================
 * /proc INTERFACE
 * ======================================================================= */
static struct proc_dir_entry *proc_dir;

/* --- /proc/nf_antidos/plugin --- */
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

/* --- /proc/nf_antidos/stats --- */
static int proc_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		   "accepted:    %lld\n"
		   "drop_bl:     %lld\n"
		   "drop_conn:   %lld\n"
		   "drop_rl:     %lld\n"
		   "auto_bans:   %lld\n",
		   atomic64_read(&stat_accepted),
		   atomic64_read(&stat_dropped_bl),
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

/* --- /proc/nf_antidos/banned ---
 * Read : liệt kê IP đang bị ban kèm TTL còn lại
 * Write: "add <ip>"  → ban thủ công (dùng ban_ttl_sec)
 *        "del <ip>"  → unban thủ công
 */
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

static ssize_t proc_banned_write(struct file *f, const char __user *buf,
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
		spin_lock_bh(&ban_lock);
		bl_ban_ip(ip);
		spin_unlock_bh(&ban_lock);
		pr_info("nf_antidos: manual ban %pI4\n", &ip);
	} else if (sscanf(cmd, "del %31s", ip_str) == 1) {
		ip = in_aton(ip_str);
		spin_lock_bh(&ban_lock);
		bl_unban_ip(ip);
		spin_unlock_bh(&ban_lock);
	} else {
		return -EINVAL;
	}
	return len;
}

static int proc_banned_open(struct inode *i, struct file *f)
{
	return single_open(f, proc_banned_show, NULL);
}

static const struct proc_ops proc_banned_ops = {
	.proc_open    = proc_banned_open,
	.proc_read    = seq_read,
	.proc_write   = proc_banned_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* --- /proc/nf_antidos/whitelist --- */
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

/* =======================================================================
 * NETFILTER OPS
 * NF_IP_PRI_FIRST = -300, chạy trước conntrack (-200)
 * ======================================================================= */
static struct nf_hook_ops nf_ops = {
	.hook     = antidos_hook,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

/* =======================================================================
 * MODULE INIT / EXIT
 * ======================================================================= */
static int __init antidos_init(void)
{
	int ret;

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
		proc_create("banned",    0644, proc_dir, &proc_banned_ops);
		proc_create("whitelist", 0644, proc_dir, &proc_whitelist_ops);
	}

	pr_info("nf_antidos: loaded (stateless) — max_conn=%u ban_thresh=%u ban_ttl=%us\n",
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

	/* Giải phóng tất cả entries */
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
		atomic64_read(&stat_dropped_bl) +
		atomic64_read(&stat_dropped_cc) +
		atomic64_read(&stat_dropped_rl));
}

module_init(antidos_init);
module_exit(antidos_exit);

/* =======================================================================
 * PLUGIN REGISTRY API
 * ======================================================================= */
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