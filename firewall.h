#ifndef __FIREWALL_H__
#define __FIREWALL_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>

// Macro define
#define PROC_NAME "firewall_config"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("~~");
MODULE_DESCRIPTION("Netfilter_firewall");

// Function prototypes
static int __init firewall_init(void);
static void __exit firewall_exit(void);
static ssize_t proc_read(struct file *file, char __user *buffer, size_t count, loff_t *pos);
static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos);
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif