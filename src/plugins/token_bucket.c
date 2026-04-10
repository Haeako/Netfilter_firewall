/* SPDX-License-Identifier: GPL-2.0
 * nf_antidos/plugins/tb_plugin.c — Token Bucket rate-limit plugin
 *
 * Cơ chế:
 *   Mỗi IP có bucket chứa tối đa TB_CAPACITY token.
 *   Mỗi gói tin tiêu thụ 1 token.
 *   Token nạp lại theo thời gian: TB_REFILL_RATE token/giây.
 *   Ưu điểm: cho phép burst hợp lệ (gửi nhanh khi bucket còn đầy).
 */
#include "rl_plugin.h"
#include <linux/jiffies.h>
#include <linux/module.h>

#define TB_CAPACITY 100   /* token tối đa / IP */
#define TB_REFILL_RATE 20 /* token nạp lại mỗi giây */

/* State riêng của plugin — nhúng rl_entry ở đầu */
struct tb_entry {
  struct rl_entry base; /* PHẢI ở đầu struct */
  unsigned long tokens;
  unsigned long last_refill; /* jiffies */
};

static void tb_init(struct rl_entry *e) {
  struct tb_entry *te = container_of(e, struct tb_entry, base);
  te->tokens = TB_CAPACITY;
  te->last_refill = jiffies;
}

static bool tb_check(struct rl_entry *e) {
  struct tb_entry *te = container_of(e, struct tb_entry, base);
  unsigned long elapsed = jiffies - te->last_refill;
  unsigned long new_tok = (elapsed * TB_REFILL_RATE) / HZ;

  if (new_tok > 0) {
    te->tokens = min(te->tokens + new_tok, (unsigned long)TB_CAPACITY);
    te->last_refill = jiffies;
  }

  if (te->tokens > 0) {
    te->tokens--;
    return true; /* ACCEPT */
  }
  return false; /* DROP */
}

static struct rl_plugin tb_plugin = {
    .name = "token_bucket",
    .entry_size = sizeof(struct tb_entry),
    .check = tb_check,
    .init_entry = tb_init,
};

static int __init tb_init_module(void) {
  return rl_plugin_register(&tb_plugin);
}

static void __exit tb_exit_module(void) { rl_plugin_unregister(&tb_plugin); }

module_init(tb_init_module);
module_exit(tb_exit_module);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Token Bucket rate-limit plugin");