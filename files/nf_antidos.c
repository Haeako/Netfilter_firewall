/* SPDX-License-Identifier: GPL-2.0
 * nf_antidos/core/nf_antidos.c
 *   Layer 1: Blacklist check      (O(1) hashtable)
 *   Layer 2: Connection limit     (per-IP conn counter)
 *   Layer 3: Rate limit plugin    (swap được qua /proc)
 *   Layer 4: Auto-ban             (violation threshold → ban TTL)
 *
 * /proc interface:
 *   /proc/nf_antidos/plugin   — đọc/ghi tên plugin active
 *   /proc/nf_antidos/stats    — thống kê
 *   /proc/nf_antidos/banned   — danh sách IP đang bị ban
 */
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nf_antidos");
MODULE_DESCRIPTION(
    "Anti-DoS Netfilter firewall — plugin rate-limit, conn limit, auto-ban");
MODULE_VERSION("1.0");

/* ─── Config ─────────────────────────────────────────────────────────────── */
static unsigned int max_conn_per_ip = 20;
static unsigned int ban_threshold = 5;   /* violation trước khi ban */
static unsigned int ban_ttl_sec = 300;   /* giây bị ban */
static unsigned int entry_ttl_sec = 120; /* giây xóa entry không dùng */
static unsigned int cleanup_sec = 30;

module_param(max_conn_per_ip, uint, 0644);
module_param(ban_threshold, uint, 0644);
module_param(ban_ttl_sec, uint, 0644);
module_param(entry_ttl_sec, uint, 0644);

/* ─── Blacklist entry ───────────────────────────────────────────────────────
 */
#define BL_HASH_BITS 10
struct ban_entry {
  __be32 src_ip;
  unsigned long expires; /* jiffies hết hạn ban */
  struct hlist_node hnode;
};

static DEFINE_HASHTABLE(ban_table, BL_HASH_BITS);
static DEFINE_SPINLOCK(ban_lock);

/* ─── Connection count table ────────────────────────────────────────────────
 */
#define CC_HASH_BITS 10
struct conn_entry {
  __be32 src_ip;
  atomic_t count;
  unsigned long last_seen;
  unsigned long violations; /* lần vượt giới hạn — dùng cho auto-ban */
  struct hlist_node hnode;
};

static DEFINE_HASHTABLE(conn_table, CC_HASH_BITS);
static DEFINE_SPINLOCK(conn_lock);

/* ─── Rate-limit entry table (plugin-owned state) ────────────────────────── */
#define RL_HASH_BITS 10
static DEFINE_HASHTABLE(rl_table, RL_HASH_BITS);
static DEFINE_SPINLOCK(rl_lock);

/* ─── Plugin registry ────────────────────────────────────────────────────── */
static LIST_HEAD(plugin_list);
static DEFINE_SPINLOCK(plugin_list_lock);
static struct rl_plugin *active_plugin = NULL;

int rl_plugin_register(struct rl_plugin *p) {
  spin_lock(&plugin_list_lock);
  list_add(&p->list, &plugin_list);
  /* đặt plugin đầu tiên đăng ký làm default */
  if (!active_plugin)
    active_plugin = p;
  spin_unlock(&plugin_list_lock);
  pr_info("nf_antidos: plugin '%s' registered\n", p->name);
  return 0;
}
EXPORT_SYMBOL(rl_plugin_register);

void rl_plugin_unregister(struct rl_plugin *p) {
  spin_lock(&plugin_list_lock);
  list_del(&p->list);
  if (active_plugin == p)
    active_plugin =
        list_empty(&plugin_list)
            ? NULL
            : list_first_entry(&plugin_list, struct rl_plugin, list);
  spin_unlock(&plugin_list_lock);
  pr_info("nf_antidos: plugin '%s' unregistered\n", p->name);
}
EXPORT_SYMBOL(rl_plugin_unregister);

struct rl_plugin *rl_plugin_get_active(void) { return active_plugin; }
EXPORT_SYMBOL(rl_plugin_get_active);

int rl_plugin_set_active(const char *name) {
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
EXPORT_SYMBOL(rl_plugin_set_active);

/* ─── Thống kê ───────────────────────────────────────────────────────────── */
static atomic64_t stat_accepted = ATOMIC64_INIT(0);
static atomic64_t stat_dropped_bl = ATOMIC64_INIT(0); /* blacklist */
static atomic64_t stat_dropped_cc = ATOMIC64_INIT(0); /* conn limit */
static atomic64_t stat_dropped_rl = ATOMIC64_INIT(0); /* rate limit */
static atomic64_t stat_auto_bans = ATOMIC64_INIT(0);

/* ─── Helpers: blacklist ────────────────────────────────────────────────────
 */
static bool bl_is_banned(__be32 ip) {
  struct ban_entry *e;
  unsigned long now = jiffies;

  hash_for_each_possible(ban_table, e, hnode, (u32)ip) {
    if (e->src_ip == ip) {
      if (time_before(now, e->expires))
        return true;
      /* TTL hết — xóa */
      hash_del(&e->hnode);
      kfree(e);
      return false;
    }
  }
  return false;
}

static void bl_ban_ip(__be32 ip) {
  struct ban_entry *e;

  /* cập nhật nếu đã có */
  hash_for_each_possible(ban_table, e, hnode, (u32)ip) {
    if (e->src_ip == ip) {
      e->expires = jiffies + ban_ttl_sec * HZ;
      return;
    }
  }

  e = kmalloc(sizeof(*e), GFP_ATOMIC);
  if (!e)
    return;
  e->src_ip = ip;
  e->expires = jiffies + ban_ttl_sec * HZ;
  hash_add(ban_table, &e->hnode, (u32)ip);
  atomic64_inc(&stat_auto_bans);
  pr_info_ratelimited("nf_antidos: auto-ban %pI4 for %us\n", &ip, ban_ttl_sec);
}

/* ─── Helpers: connection count ──────────────────────────────────────────── */
static struct conn_entry *cc_get_or_create(__be32 ip) {
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
  e->src_ip = ip;
  e->last_seen = jiffies;
  e->violations = 0;
  atomic_set(&e->count, 0);
  hash_add(conn_table, &e->hnode, (u32)ip);
  return e;
}

/* ─── Helpers: rate-limit entry ──────────────────────────────────────────── */
static struct rl_entry *rl_get_or_create(__be32 ip, struct rl_plugin *plugin) {
  struct rl_entry *e;

  hash_for_each_possible(rl_table, e, hnode, (u32)ip) {
    if (e->src_ip == ip) {
      e->last_seen = jiffies;
      return e;
    }
  }
  /* kmalloc size = plugin->entry_size (bao gồm cả rl_entry header) */
  e = kmalloc(plugin->entry_size, GFP_ATOMIC);
  if (!e)
    return NULL;
  e->src_ip = ip;
  e->last_seen = jiffies;
  hash_add(rl_table, &e->hnode, (u32)ip);
  plugin->init_entry(e);
  return e;
}

/* ─── Netfilter hook ─────────────────────────────────────────────────────── */
static unsigned int antidos_hook(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state) {
  struct iphdr *iph;
  __be32 src;
  struct conn_entry *cc;
  struct rl_entry *re;
  struct rl_plugin *plugin;

  if (!skb)
    return NF_ACCEPT;
  iph = ip_hdr(skb);
  if (!iph)
    return NF_ACCEPT;
  src = iph->saddr;

  /* ── Layer 1: Blacklist ─────────────────────────── */
  spin_lock_bh(&ban_lock);
  if (bl_is_banned(src)) {
    spin_unlock_bh(&ban_lock);
    atomic64_inc(&stat_dropped_bl);
    return NF_DROP;
  }
  spin_unlock_bh(&ban_lock);

  /* ── Layer 2: Connection limit ──────────────────── */
  spin_lock_bh(&conn_lock);
  cc = cc_get_or_create(src);
  if (cc) {
    int cur = atomic_read(&cc->count);
    if (cur >= (int)max_conn_per_ip) {
      cc->violations++;
      if (cc->violations >= ban_threshold) {
        /* ban IP, reset counter */
        spin_lock_bh(&ban_lock);
        bl_ban_ip(src);
        spin_unlock_bh(&ban_lock);
        cc->violations = 0;
      }
      spin_unlock_bh(&conn_lock);
      atomic64_inc(&stat_dropped_cc);
      return NF_DROP;
    }
    atomic_inc(&cc->count);
  }
  spin_unlock_bh(&conn_lock);

  /* ── Layer 3: Rate-limit plugin ─────────────────── */
  spin_lock_bh(&plugin_list_lock);
  plugin = active_plugin;
  spin_unlock_bh(&plugin_list_lock);

  if (plugin) {
    spin_lock_bh(&rl_lock);
    re = rl_get_or_create(src, plugin);
    if (re && !plugin->check(re)) {
      /* rate limit exceeded */
      spin_unlock_bh(&rl_lock);

      /* tăng violation cho auto-ban */
      spin_lock_bh(&conn_lock);
      cc = cc_get_or_create(src);
      if (cc) {
        cc->violations++;
        if (cc->violations >= ban_threshold) {
          spin_lock_bh(&ban_lock);
          bl_ban_ip(src);
          spin_unlock_bh(&ban_lock);
          cc->violations = 0;
        }
      }
      spin_unlock_bh(&conn_lock);

      atomic64_inc(&stat_dropped_rl);
      return NF_DROP;
    }
    spin_unlock_bh(&rl_lock);
  }

  atomic64_inc(&stat_accepted);
  return NF_ACCEPT;
}

/* ─── Cleanup timer ──────────────────────────────────────────────────────── */
static struct timer_list cleanup_timer;

static void do_cleanup(struct timer_list *t) {
  unsigned long ttl = entry_ttl_sec * HZ;
  unsigned long now = jiffies;
  int bkt;
  struct hlist_node *tmp;

  /* cleanup conn_table */
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

  /* cleanup rl_table */
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

  /* cleanup ban_table (expired bans) */
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

/* ─── /proc interface ────────────────────────────────────────────────────── */
static struct proc_dir_entry *proc_dir;

/* /proc/nf_antidos/plugin — đọc/ghi tên plugin */
static ssize_t proc_plugin_write(struct file *f, const char __user *buf,
                                 size_t len, loff_t *off) {
  char name[64] = {};
  if (len >= sizeof(name))
    return -EINVAL;
  if (copy_from_user(name, buf, len))
    return -EFAULT;
  /* strip newline */
  name[strcspn(name, "\n")] = 0;
  if (rl_plugin_set_active(name) < 0) {
    pr_warn("nf_antidos: unknown plugin '%s'\n", name);
    return -ENOENT;
  }
  return len;
}

static int proc_plugin_show(struct seq_file *m, void *v) {
  struct rl_plugin *p;
  spin_lock(&plugin_list_lock);
  seq_printf(m, "active: %s\navailable:",
             active_plugin ? active_plugin->name : "(none)");
  list_for_each_entry(p, &plugin_list, list) seq_printf(m, " %s", p->name);
  seq_putc(m, '\n');
  spin_unlock(&plugin_list_lock);
  return 0;
}
static int proc_plugin_open(struct inode *i, struct file *f) {
  return single_open(f, proc_plugin_show, NULL);
}

static const struct proc_ops proc_plugin_ops = {
    .proc_open = proc_plugin_open,
    .proc_read = seq_read,
    .proc_write = proc_plugin_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* /proc/nf_antidos/stats */
static int proc_stats_show(struct seq_file *m, void *v) {
  seq_printf(m,
             "accepted:    %lld\n"
             "drop_bl:     %lld\n"
             "drop_conn:   %lld\n"
             "drop_rl:     %lld\n"
             "auto_bans:   %lld\n",
             atomic64_read(&stat_accepted), atomic64_read(&stat_dropped_bl),
             atomic64_read(&stat_dropped_cc), atomic64_read(&stat_dropped_rl),
             atomic64_read(&stat_auto_bans));
  return 0;
}
static int proc_stats_open(struct inode *i, struct file *f) {
  return single_open(f, proc_stats_show, NULL);
}
static const struct proc_ops proc_stats_ops = {
    .proc_open = proc_stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* /proc/nf_antidos/banned */
static int proc_banned_show(struct seq_file *m, void *v) {
  struct ban_entry *e;
  unsigned long now = jiffies;
  int bkt;

  spin_lock_bh(&ban_lock);
  hash_for_each(ban_table, bkt, e, hnode) {
    long rem = (long)(e->expires - now) / HZ;
    if (rem > 0)
      seq_printf(m, "%pI4  ttl=%lds\n", &e->src_ip, rem);
  }
  spin_unlock_bh(&ban_lock);
  return 0;
}
static int proc_banned_open(struct inode *i, struct file *f) {
  return single_open(f, proc_banned_show, NULL);
}
static const struct proc_ops proc_banned_ops = {
    .proc_open = proc_banned_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* ─── Netfilter ops ─────────────────────────────────────────────────────────
 */
static struct nf_hook_ops nf_ops = {
    .hook = antidos_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

/* ─── Module init / exit ────────────────────────────────────────────────────
 */
static int __init antidos_init(void) {
  int ret;

  hash_init(ban_table);
  hash_init(conn_table);
  hash_init(rl_table);

  ret = nf_register_net_hook(&init_net, &nf_ops);
  if (ret) {
    pr_err("nf_antidos: hook register failed (%d)\n", ret);
    return ret;
  }

  timer_setup(&cleanup_timer, do_cleanup, 0);
  mod_timer(&cleanup_timer, jiffies + cleanup_sec * HZ);

  proc_dir = proc_mkdir("nf_antidos", NULL);
  if (proc_dir) {
    proc_create("plugin", 0644, proc_dir, &proc_plugin_ops);
    proc_create("stats", 0444, proc_dir, &proc_stats_ops);
    proc_create("banned", 0444, proc_dir, &proc_banned_ops);
  }

  pr_info("nf_antidos: loaded — max_conn=%u ban_thresh=%u ban_ttl=%us\n",
          max_conn_per_ip, ban_threshold, ban_ttl_sec);
  return 0;
}

static void __exit antidos_exit(void) {
  int bkt;
  struct hlist_node *tmp;

  nf_unregister_net_hook(&init_net, &nf_ops);
  del_timer_sync(&cleanup_timer);

  if (proc_dir) {
    remove_proc_entry("plugin", proc_dir);
    remove_proc_entry("stats", proc_dir);
    remove_proc_entry("banned", proc_dir);
    remove_proc_entry("nf_antidos", NULL);
  }

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
          atomic64_read(&stat_dropped_bl) + atomic64_read(&stat_dropped_cc) +
              atomic64_read(&stat_dropped_rl));
}

module_init(antidos_init);
module_exit(antidos_exit);