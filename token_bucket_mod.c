#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>

#define PROC_FILENAME "token_bucket_config"

// Cấu trúc Token Bucket
static long rate = 10;        // Số gói tin cho phép mỗi giây
static long capacity = 20;    // Dung lượng tối đa của bucket
static long tokens = 20;      // Số lượng token hiện tại
static unsigned long last_jiffies = 0;
static spinlock_t bucket_lock;

// Netfilter hook
static struct nf_hook_ops nfho;

// Hàm cập nhật token dựa trên thời gian trôi qua
void refill_tokens(void) {
    unsigned long now = jiffies;
    unsigned long delta_jiffies = now - last_jiffies;
    long tokens_to_add = (delta_jiffies * rate) / HZ;

    if (tokens_to_add > 0) {
        tokens += tokens_to_add;
        if (tokens > capacity) tokens = capacity;
        last_jiffies = now;
    }
}

// Hàm xử lý gói tin
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    unsigned int verdict;
    
    spin_lock(&bucket_lock);
    refill_tokens();

    if (tokens >= 1) {
        tokens--;
        verdict = NF_ACCEPT; // Cho phép qua
    } else {
        verdict = NF_DROP;   // Bị loại bỏ
        if (printk_ratelimit())
            pr_info("Token Bucket: Packet dropped (no tokens)\n");
    }
    spin_unlock(&bucket_lock);

    return verdict;
}

// Xử lý ghi vào file /proc để update thông số
static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *data) {
    char input[64];
    long new_rate, new_cap;

    if (count > sizeof(input) - 1) return -EINVAL;
    if (copy_from_user(input, buffer, count)) return -EFAULT;
    input[count] = '\0';

    // Định dạng: "rate capacity" ví dụ: "100 200"
    if (sscanf(input, "%ld %ld", &new_rate, &new_cap) == 2) {
        spin_lock(&bucket_lock);
        rate = new_rate;
        capacity = new_cap;
        tokens = capacity; // Reset bucket
        spin_unlock(&bucket_lock);
        pr_info("Token Bucket: Updated - Rate: %ld, Capacity: %ld\n", rate, capacity);
    }
    return count;
}

// Xử lý đọc file /proc để xem thông số hiện tại
static ssize_t proc_read(struct file *file, char __user *buffer, size_t count, loff_t *data) {
    char output[64];
    int len;
    
    if (*data > 0) return 0;
    
    len = sprintf(output, "Rate: %ld\nCapacity: %ld\nTokens: %ld\n", rate, capacity, tokens);
    if (copy_to_user(buffer, output, len)) return -EFAULT;
    
    *data = len;
    return len;
}

static const struct proc_ops proc_fops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

// Khởi tạo module
static int __init token_bucket_init(void) {
    spin_lock_init(&bucket_lock);
    last_jiffies = jiffies;

    // Tạo file /proc/token_bucket_config
    proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);

    // Cấu hình Netfilter Hook
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING; // Chặn ngay khi gói tin vào
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);

    pr_info("Token Bucket Module Loaded\n");
    return 0;
}

// Gỡ bỏ module
static void __exit token_bucket_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    remove_proc_entry(PROC_FILENAME, NULL);
    pr_info("Token Bucket Module Unloaded\n");
}

module_init(token_bucket_init);
module_exit(token_bucket_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Admin");
MODULE_DESCRIPTION("Netfilter Token Bucket Rate Limiter");