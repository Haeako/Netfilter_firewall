/* SPDX-License-Identifier: GPL-2.0
 * nf_antidos/plugins/fw_plugin.c — Fixed Window Counter rate-limit plugin
 *
 * Cơ chế:
 *   Chia thời gian thành các window cố định FW_WINDOW_SEC giây.
 *   Đếm số gói trong window hiện tại.
 *   Nếu count > FW_MAX_COUNT → DROP cho đến hết window.
 *   Nhược điểm: boundary burst — kẻ tấn công có thể gửi 2× limit
 *   bằng cách gửi cuối window này + đầu window sau.
 *   Đơn giản nhất, overhead thấp nhất.
 */
#include "rl_plugin.h"
#include <linux/jiffies.h>
#include <linux/module.h>

#define FW_WINDOW_SEC 1 /* độ dài window (giây) */
#define FW_MAX_COUNT 50 /* gói tối đa mỗi window */

struct fw_entry {
  struct rl_entry base;
  unsigned long count;        /* số gói trong window hiện tại */
  unsigned long window_start; /* jiffies đầu window */
};

static void fw_init(struct rl_entry *e) {
  struct fw_entry *fe = container_of(e, struct fw_entry, base);
  fe->count = 0;
  fe->window_start = jiffies;
}

static bool fw_check(struct rl_entry *e) {
  struct fw_entry *fe = container_of(e, struct fw_entry, base);
  unsigned long elapsed = jiffies - fe->window_start;

  /* window mới → reset counter */
  if (elapsed >= FW_WINDOW_SEC * HZ) {
    fe->count = 0;
    fe->window_start = jiffies;
  }

  if (fe->count < FW_MAX_COUNT) {
    fe->count++;
    return true; /* ACCEPT */
  }
  return false; /* DROP */
}

static struct rl_plugin fw_plugin = {
    .name = "fixed_window",
    .entry_size = sizeof(struct fw_entry),
    .check = fw_check,
    .init_entry = fw_init,
};

static int __init fw_init_module(void) {
  return rl_plugin_register(&fw_plugin);
}

static void __exit fw_exit_module(void) { rl_plugin_unregister(&fw_plugin); }

module_init(fw_init_module);
module_exit(fw_exit_module);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fixed Window Counter rate-limit plugin");