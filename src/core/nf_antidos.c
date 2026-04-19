/* SPDX-License-Identifier: GPL-2.0
 * nf_antidos.c - Version 2.1 (Single token bucket per IP, all protocols)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/hashtable.h>
#include <linux/timer.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#define ANTIDOS_HASH_BITS 10
#define MAX_DOS_ENTRIES 4096

struct dos_entry {
    __be32        src_ip;
    unsigned long last_seen;
    unsigned long ban_until;
    unsigned long last_refill;
    uint32_t      tokens;
    struct hlist_node hnode;
};

static DEFINE_HASHTABLE(dos_table, ANTIDOS_HASH_BITS);
static DEFINE_SPINLOCK(antidos_lock);
static atomic_t entry_count = ATOMIC_INIT(0);

static unsigned int rate    = 50;
static unsigned int burst   = 5000;
static unsigned int ban_sec = 30;

module_param(rate,    uint, 0644);
module_param(burst,   uint, 0644);
module_param(ban_sec, uint, 0644);

static atomic64_t stat_accepted = ATOMIC64_INIT(0);
static atomic64_t stat_dropped  = ATOMIC64_INIT(0);
static atomic64_t stat_bans     = ATOMIC64_INIT(0);

static bool token_bucket_check(uint32_t *tokens, unsigned long *last_jiffies)
{
    unsigned long now   = jiffies;
    unsigned long diff  = now - *last_jiffies;
    uint32_t refill     = (uint32_t)(jiffies_to_msecs(diff) * rate / 1000);

    if (refill > 0) {
        *tokens += refill;
        if (*tokens > burst)
            *tokens = burst;
        *last_jiffies = now;
    }

    if (*tokens > 0) {
        (*tokens)--;
        return true;
    }
    return false;
}

/* ================== NETFILTER HOOK ================== */

static unsigned int antidos_hook(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr     *iph;
    struct dos_entry *found;
    __be32 src;
    bool allowed;

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph) return NF_DROP;

    /* Bỏ qua loopback */
    if (skb->dev && (skb->dev->flags & IFF_LOOPBACK))
        return NF_ACCEPT;

    src = iph->saddr;

    spin_lock_bh(&antidos_lock);

    /* 1. Tìm entry */
    found = NULL;
    hash_for_each_possible(dos_table, found, hnode, (u32)src) {
        if (found->src_ip == src) break;
        found = NULL;
    }

    /* 2. Tạo mới nếu chưa có */
    if (!found) {
        if (atomic_read(&entry_count) >= MAX_DOS_ENTRIES) {
            spin_unlock_bh(&antidos_lock);
            atomic64_inc(&stat_dropped);
            return NF_ACCEPT;
        }
        found = kmalloc(sizeof(*found), GFP_ATOMIC);
        if (!found) {
            spin_unlock_bh(&antidos_lock);
            return NF_ACCEPT;
        }
        found->src_ip      = src;
        found->last_seen   = jiffies;
        found->ban_until   = 0;
        found->last_refill = jiffies;
        found->tokens      = burst;
        hash_add(dos_table, &found->hnode, (u32)src);
        atomic_inc(&entry_count);
    }

    /* 3. Đang bị ban? */
    if (found->ban_until && time_before(jiffies, found->ban_until)) {
        found->last_seen = jiffies;
        spin_unlock_bh(&antidos_lock);
        atomic64_inc(&stat_dropped);
        return NF_DROP;
    }

    /* 4. Token bucket */
    allowed = token_bucket_check(&found->tokens, &found->last_refill);
    found->last_seen = jiffies;

    if (!allowed) {
        found->ban_until = jiffies + (ban_sec * HZ);
        atomic64_inc(&stat_bans);
        pr_warn_ratelimited("nf_antidos: BAN %pI4 for %u sec\n",
                            &found->src_ip, ban_sec);
        spin_unlock_bh(&antidos_lock);
        atomic64_inc(&stat_dropped);
        return NF_DROP;
    }

    spin_unlock_bh(&antidos_lock);
    atomic64_inc(&stat_accepted);
    return NF_ACCEPT;
}

/* ================== /PROC ================== */

static int proc_stats_show(struct seq_file *m, void *v)
{
    seq_printf(m,
        "Accepted:  %lld\n"
        "Dropped:   %lld\n"
        "Auto-Bans: %lld\n"
        "Entries:   %d/%d\n"
        "\n--- Config ---\n"
        "rate=%u/s  burst=%u  ban_sec=%u\n",
        atomic64_read(&stat_accepted),
        atomic64_read(&stat_dropped),
        atomic64_read(&stat_bans),
        atomic_read(&entry_count), MAX_DOS_ENTRIES,
        rate, burst, ban_sec);
    return 0;
}

static int proc_banned_show(struct seq_file *m, void *v)
{
    struct dos_entry *e;
    int bkt;
    unsigned long now = jiffies;

    seq_printf(m, "%-18s %s\n", "IP", "Remaining(s)");
    spin_lock_bh(&antidos_lock);
    hash_for_each(dos_table, bkt, e, hnode) {
        if (e->ban_until && time_before(now, e->ban_until))
            seq_printf(m, "%-18pI4 %lu\n",
                       &e->src_ip, (e->ban_until - now) / HZ);
    }
    spin_unlock_bh(&antidos_lock);
    return 0;
}

static int proc_ips_show(struct seq_file *m, void *v)
{
    struct dos_entry *e;
    int bkt;
    unsigned long now = jiffies;

    seq_printf(m, "%-18s %-8s %-10s %-12s\n",
               "IP", "Status", "Tokens", "Ban_remain(s)");
    seq_puts(m, "---------------------------------------------------\n");
    seq_printf(m, "%-18s %-8s %-10u\n", "(max)", "", burst);
    seq_puts(m, "---------------------------------------------------\n");

    spin_lock_bh(&antidos_lock);
    hash_for_each(dos_table, bkt, e, hnode) {
        bool banned       = e->ban_until && time_before(now, e->ban_until);
        unsigned long rem = banned ? (e->ban_until - now) / HZ : 0;
        seq_printf(m, "%-18pI4 %-8s %-10u %-12lu\n",
                   &e->src_ip,
                   banned ? "BANNED" : "OK",
                   e->tokens, rem);
    }
    spin_unlock_bh(&antidos_lock);
    return 0;
}

/* ================== CLEANUP & INIT ================== */

static struct timer_list cleanup_timer;

static void do_cleanup(struct timer_list *t)
{
    struct dos_entry *e;
    struct hlist_node *tmp;
    int bkt;

    spin_lock_bh(&antidos_lock);
    hash_for_each_safe(dos_table, bkt, tmp, e, hnode) {
        if (time_after(jiffies, e->last_seen + (600 * HZ))) {
            hash_del(&e->hnode);
            kfree(e);
            atomic_dec(&entry_count);
        }
    }
    spin_unlock_bh(&antidos_lock);
    mod_timer(&cleanup_timer, jiffies + (60 * HZ));
}

static struct nf_hook_ops nf_ops = {
    .hook     = antidos_hook,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = -300
};

static int __init antidos_init(void)
{
    hash_init(dos_table);
    nf_register_net_hook(&init_net, &nf_ops);
    timer_setup(&cleanup_timer, do_cleanup, 0);
    mod_timer(&cleanup_timer, jiffies + (60 * HZ));
    proc_create_single("nf_antidos_stats",  0444, NULL, proc_stats_show);
    proc_create_single("nf_antidos_banned", 0444, NULL, proc_banned_show);
    proc_create_single("nf_antidos_ips",    0444, NULL, proc_ips_show);
    pr_info("nf_antidos: loaded (rate=%u/s burst=%u ban=%us)\n",
            rate, burst, ban_sec);
    return 0;
}

static void __exit antidos_exit(void)
{
    struct dos_entry *e;
    struct hlist_node *tmp;
    int bkt;

    nf_unregister_net_hook(&init_net, &nf_ops);
    del_timer_sync(&cleanup_timer);
    remove_proc_entry("nf_antidos_stats",  NULL);
    remove_proc_entry("nf_antidos_banned", NULL);
    remove_proc_entry("nf_antidos_ips",    NULL);
    spin_lock_bh(&antidos_lock);
    hash_for_each_safe(dos_table, bkt, tmp, e, hnode) {
        hash_del(&e->hnode);
        kfree(e);
    }
    spin_unlock_bh(&antidos_lock);
}

module_init(antidos_init);
module_exit(antidos_exit);
MODULE_LICENSE("GPL");
