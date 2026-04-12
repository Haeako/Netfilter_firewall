/* SPDX-License-Identifier: GPL-2.0
 * nf_antidos.c - Version 1.2 (Fixed Critical Bugs)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/hashtable.h>
#include <linux/timer.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/inet.h>
#include <linux/slab.h>

#define ANTIDOS_HASH_BITS 10
#define MAX_DOS_ENTRIES 4096  /* Giới hạn tránh tràn RAM khi bị tấn công triệu IP */

struct dos_entry {
    __be32 src_ip;
    unsigned long last_seen;
    unsigned long ban_until;
    
    /* Tách biệt last_refill cho từng bucket để fix logic refill */
    unsigned long last_refill_syn;
    unsigned long last_refill_icmp;
    unsigned long last_refill_web;

    uint32_t tokens_syn;
    uint32_t tokens_icmp;
    uint32_t tokens_web;

    struct hlist_node hnode;
};

static DEFINE_HASHTABLE(dos_table, ANTIDOS_HASH_BITS);
static DEFINE_SPINLOCK(antidos_lock);
static atomic_t entry_count = ATOMIC_INIT(0);

static unsigned int rate_syn  = 20;
static unsigned int rate_icmp = 5;
static unsigned int rate_web  = 100;
static unsigned int burst     = 30;
static unsigned int ban_sec   = 300;

module_param(rate_syn,  uint, 0644);
module_param(rate_icmp, uint, 0644);
module_param(rate_web,  uint, 0644);
module_param(ban_sec,   uint, 0644);

static atomic64_t stat_accepted = ATOMIC64_INIT(0);
static atomic64_t stat_dropped  = ATOMIC64_INIT(0);
static atomic64_t stat_bans     = ATOMIC64_INIT(0);

/* Fix: Cập nhật last_jiffies ngay trong hàm để refill chính xác */
static bool token_bucket_check(uint32_t *tokens, unsigned int rate, unsigned long *last_jiffies) {
    unsigned long now = jiffies;
    unsigned long diff = now - *last_jiffies;
    uint32_t refill = (jiffies_to_msecs(diff) * rate) / 1000;

    if (refill > 0) {
        *tokens += refill;
        if (*tokens > burst) *tokens = burst;
        *last_jiffies = now; /* Cập nhật mốc refill mới */
    }

    if (*tokens > 0) {
        (*tokens)--;
        return true;
    }
    return false; 
}

/* ================== NETFILTER HOOK ================== */

static unsigned int antidos_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *th;
    struct dos_entry *found;
    __be32 src;
    bool allowed = true;
    unsigned int ip_hlen;

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;
    
    src = iph->saddr;
    found = NULL;
    ip_hlen = iph->ihl * 4;

    spin_lock_bh(&antidos_lock);
	if (skb->dev && (skb->dev->flags & IFF_LOOPBACK))
    {
        spin_unlock_bh(&antidos_lock);
		return NF_ACCEPT;
    }
        /* 1. Tìm hoặc tạo IP entry */
    hash_for_each_possible(dos_table, found, hnode, (u32)src) {
        if (found->src_ip == src) break;
    }

    if (!found) {
        /* Chống OOM: Không tạo thêm nếu bảng băm đã đầy */
        if (atomic_read(&entry_count) >= MAX_DOS_ENTRIES) {
            spin_unlock_bh(&antidos_lock);
            return NF_DROP;
        }
        found = kmalloc(sizeof(*found), GFP_ATOMIC);
        if (!found) { spin_unlock_bh(&antidos_lock); return NF_ACCEPT; }
        
        found->src_ip = src;
        found->last_seen = jiffies;
        found->ban_until = 0;
        found->last_refill_syn = jiffies;
        found->last_refill_icmp = jiffies;
        found->last_refill_web = jiffies;
        found->tokens_syn = burst;
        found->tokens_icmp = burst;
        found->tokens_web = burst;
        
        hash_add(dos_table, &found->hnode, (u32)src);
        atomic_inc(&entry_count);
    }

    /* 2. Kiểm tra trạng thái bị BAN */
    if (found->ban_until && time_before(jiffies, found->ban_until)) {
        found->last_seen = jiffies;
        spin_unlock_bh(&antidos_lock);
        atomic64_inc(&stat_dropped);
        return NF_DROP;
    }

    /* 3. Phân loại packet và check giới hạn tốc độ */
    if (iph->protocol == IPPROTO_TCP) {
        /* Fix: Kiểm tra độ dài skb tránh crash khi truy cập th */
        if (skb->len >= ip_hlen + sizeof(struct tcphdr)) {
            th = (struct tcphdr *)((u8 *)iph + ip_hlen);
            if (th->syn && !th->ack) {
                allowed = token_bucket_check(&found->tokens_syn, rate_syn, &found->last_refill_syn);
            } else if (ntohs(th->dest) == 80 || ntohs(th->dest) == 443) {
                allowed = token_bucket_check(&found->tokens_web, rate_web, &found->last_refill_web);
            }
        }
    } else if (iph->protocol == IPPROTO_ICMP) {
        allowed = token_bucket_check(&found->tokens_icmp, rate_icmp, &found->last_refill_icmp);
    }

    found->last_seen = jiffies;

    /* 4. Xử lý vi phạm */
    if (!allowed) {
        found->ban_until = jiffies + (ban_sec * HZ);
        atomic64_inc(&stat_bans);
        pr_warn_ratelimited("nf_antidos: BAN %pI4 for %u sec (SYN/ICMP/WEB tokens: %u/%u/%u)\n",
            &found->src_ip, ban_sec, found->tokens_syn, found->tokens_icmp, found->tokens_web);

        spin_unlock_bh(&antidos_lock);
        atomic64_inc(&stat_dropped);
        return NF_DROP;
    }

    spin_unlock_bh(&antidos_lock);
    atomic64_inc(&stat_accepted);
    return NF_ACCEPT;
}

/* ================== GIAO DIỆN /PROC ================== */

static int proc_stats_show(struct seq_file *m, void *v) {
    seq_printf(m, "Accepted:  %lld\nDropped:   %lld\nAuto-Bans: %lld\nEntries:   %d/%d\n", 
               atomic64_read(&stat_accepted), atomic64_read(&stat_dropped), 
               atomic64_read(&stat_bans), atomic_read(&entry_count), MAX_DOS_ENTRIES);
    return 0;
}

static int proc_banned_show(struct seq_file *m, void *v) {
    struct dos_entry *e;
    int bkt;
    unsigned long now = jiffies;
    seq_printf(m, "%-18s %s\n", "IP", "Remaining(s)");
    spin_lock_bh(&antidos_lock);
    hash_for_each(dos_table, bkt, e, hnode) {
        if (e->ban_until && time_before(now, e->ban_until)) {
            seq_printf(m, "%-18pI4 %lu\n", &e->src_ip, (e->ban_until - now) / HZ);
        }
    }
    spin_unlock_bh(&antidos_lock);
    return 0;
}

/* ================== DỌN DẸP & KHỞI TẠO ================== */

static struct timer_list cleanup_timer;
static void do_cleanup(struct timer_list *t) {
    struct dos_entry *e;
    struct hlist_node *tmp;
    int bkt;
    spin_lock_bh(&antidos_lock);
    hash_for_each_safe(dos_table, bkt, tmp, e, hnode) {
        /* Xóa entry nếu idle 10 phút hoặc đã hết hạn ban để làm trống bảng */
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
    .hook = antidos_hook, .pf = NFPROTO_IPV4, .hooknum = NF_INET_PRE_ROUTING, .priority = -300
};

static int __init antidos_init(void) {
    hash_init(dos_table);
    nf_register_net_hook(&init_net, &nf_ops);
    timer_setup(&cleanup_timer, do_cleanup, 0);
    mod_timer(&cleanup_timer, jiffies + (60 * HZ));
    proc_create_single("nf_antidos_stats", 0444, NULL, proc_stats_show);
    proc_create_single("nf_antidos_banned", 0444, NULL, proc_banned_show);
    return 0;
}

static void __exit antidos_exit(void) {
    struct dos_entry *e;
    struct hlist_node *tmp;
    int bkt;
    nf_unregister_net_hook(&init_net, &nf_ops);
    del_timer_sync(&cleanup_timer);
    remove_proc_entry("nf_antidos_stats", NULL);
    remove_proc_entry("nf_antidos_banned", NULL);
    spin_lock_bh(&antidos_lock);
    hash_for_each_safe(dos_table, bkt, tmp, e, hnode) { hash_del(&e->hnode); kfree(e); }
    spin_unlock_bh(&antidos_lock);
}

module_init(antidos_init);
module_exit(antidos_exit);
MODULE_LICENSE("GPL");