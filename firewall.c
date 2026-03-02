#include "firewall.h"

// Private vars
static struct nf_hook_ops nfho;
static struct proc_dir_entry *proc_file;
static char blocked_ip_str[16] = "192.168.1.100";
static __be32 blocked_ip_binary;

/**
 * hook_func() - Netfilter hook function to filter packets based on source IP
 * @priv: Private data (unused)
 * @skb: Socket buffer containing the packet
 * @state: Netfilter hook state information
 *
 * This function is called by netfilter at the NF_INET_PRE_ROUTING hook point
 * for every incoming IPv4 packet. It checks if the source IP matches the
 * blocked IP address and drops the packet if it matches.
 *
 * The function performs the following checks:
 * 1. Validates that the socket buffer is not NULL
 * 2. Extracts and validates the IP header
 * 3. Compares source IP with the blocked IP
 * 4. Drops matching packets and logs the event
 *
 * Context: Called in softirq context. Cannot sleep.
 *          No locks are taken or expected.
 *
 * Return: NF_DROP if packet source IP matches blocked IP,
 *         NF_ACCEPT otherwise
 */
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

/**
 * proc_read() - Read handler for /proc/firewall_config
 * @file: File pointer (unused)
 * @buffer: User-space buffer to write data to
 * @count: Maximum number of bytes to read
 * @pos: Current file position
 *
 * Provides the currently blocked IP address as a string to user-space
 * through the proc filesystem. The IP is formatted as a dotted-decimal
 * string followed by a newline.
 *
 * This function uses a temporary kernel buffer to format the output
 * and then copies it safely to user-space using copy_to_user().
 *
 * Context: Process context. Can sleep.
 * 
 * Return: Number of bytes read on success,
 *         0 if already read (pos > 0),
 *         -EFAULT if copy_to_user fails
 */
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

/**
 * proc_write() - Write handler for /proc/firewall_config
 * @file: File pointer (unused)
 * @buffer: User-space buffer containing new IP address
 * @count: Number of bytes to write
 * @pos: Current file position (unused)
 *
 * Allows user-space to update the blocked IP address by writing to
 * /proc/firewall_config. Accepts an IP address in dotted-decimal format
 * (e.g., "192.168.1.100").
 *
 * The function performs the following:
 * 1. Validates input length (max 15 chars for IP address)
 * 2. Safely copies data from user-space
 * 3. Removes trailing newline if present
 * 4. Converts IP string to binary format
 * 5. Updates both string and binary representations
 * 6. Logs the change
 *
 * Context: Process context. Can sleep.
 *
 * Return: Number of bytes written on success,
 *         -EINVAL if input is too long (>15 bytes),
 *         -EFAULT if copy_from_user fails
 */
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

/**
 * firewall_init() - Initialize the firewall kernel module
 *
 * Module initialization function that sets up the firewall by:
 * 1. Converting the default blocked IP to binary format
 * 2. Creating a proc filesystem entry at /proc/firewall_config
 * 3. Registering a netfilter hook at NF_INET_PRE_ROUTING
 *
 * The netfilter hook is registered with NF_IP_PRI_FIRST priority to
 * ensure it runs early in the packet processing pipeline, before
 * connection tracking and other netfilter modules.
 *
 * If procfs creation fails, the function returns immediately without
 * registering the netfilter hook. If hook registration fails, the
 * proc entry is cleaned up before returning.
 *
 * Context: Called during module loading in process context.
 *          Can sleep.
 *
 * Return: 0 on success,
 *         -ENOMEM if proc entry creation fails,
 *         -EFAULT if netfilter hook registration fails
 */
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

/**
 * firewall_exit() - Clean up and unload the firewall module
 *
 * Module cleanup function that safely tears down all resources:
 * 1. Unregisters the netfilter hook to stop packet filtering
 * 2. Removes the proc filesystem entry
 * 3. Logs the module unload event
 *
 * This function ensures proper cleanup in reverse order of
 * initialization to prevent race conditions and resource leaks.
 *
 * Context: Called during module removal in process context.
 *          Can sleep.
 *
 * Return: void
 */
static void __exit firewall_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    proc_remove(proc_file);
    printk(KERN_INFO "Firewall: Module unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);