#include "firewall.h"

// Private vars
static struct nf_hook_ops nfho;
static struct proc_dir_entry *proc_file;
static char blocked_ip_str[16] = "192.168.1.100";
static __be32 blocked_ip_binary;

// Hook function
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;
    if (ip_header->saddr == blocked_ip_binary)
    {
        printk(KERN_INFO "Firewall: Blocked IP %pI4\n", &ip_header->saddr);
        return NF_DROP;
    }

    return NF_ACCEPT;
}

// Proc read function
static ssize_t proc_read(struct file *file, char __user *buffer, size_t count, loff_t *pos)
{
    int len;
    char temp[32];
    
    if (*pos > 0)
        return 0;
    
    len = snprintf(temp, sizeof(temp), "%s\n", blocked_ip_str);
    
    if (count < len)
        len = count;
    
    if (copy_to_user(buffer, temp, len))
        return -EFAULT;
    
    *pos = len;
    return len;
}

// Proc write function
static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    char temp[16];
    
    if (count > 15)
        return -EINVAL;
    
    if (copy_from_user(temp, buffer, count))
        return -EFAULT;
    
    temp[count] = '\0';
    
    // Remove newline if present
    if (temp[count-1] == '\n')
        temp[count-1] = '\0';
    
    strncpy(blocked_ip_str, temp, sizeof(blocked_ip_str) - 1);
    blocked_ip_str[sizeof(blocked_ip_str) - 1] = '\0';
    
    blocked_ip_binary = in_aton(blocked_ip_str);
    
    printk(KERN_INFO "Firewall: Updated blocked IP to %s (%pI4)\n", 
           blocked_ip_str, &blocked_ip_binary);
    
    return count;
}

// Proc ops structure
static struct proc_ops pops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

// Module init
static int __init firewall_init(void)
{
    // Convert initial IP to binary
    blocked_ip_binary = in_aton(blocked_ip_str);
    
    // Create procfs entry
    proc_file = proc_create(PROC_NAME, 0666, NULL, &pops);
    if (!proc_file) {
        printk(KERN_ERR "Firewall: Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    // Register netfilter hook
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, &nfho)) {
        proc_remove(proc_file);
        printk(KERN_ERR "Firewall: Failed to register hook\n");
        return -EFAULT;
    }

    printk(KERN_INFO "Firewall: Module loaded, blocking IP %s\n", blocked_ip_str);
    return 0;
}

// Module exit
static void __exit firewall_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    proc_remove(proc_file);
    printk(KERN_INFO "Firewall: Module unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);