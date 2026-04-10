/* SPDX-License-Identifier: GPL-2.0
 * nf_antidos/plugins/rl_plugin.h
 *
 * Plugin interface cho rate-limiting.
 * Mỗi thuật toán (Token Bucket, Leaky Bucket, Fixed Window)
 * implement struct rl_plugin và đăng ký qua rl_plugin_register().
 */
#ifndef RL_PLUGIN_H
#define RL_PLUGIN_H

#include <linux/list.h>
#include <linux/types.h>

/* Forward declaration — mỗi plugin tự định nghĩa state của mình */
struct rl_entry;

/**
 * struct rl_plugin — vtable mỗi thuật toán phải implement
 *
 * @name:        tên ngắn hiển thị trong /proc ("token_bucket", ...)
 * @entry_size:  sizeof(state riêng của plugin) — dùng để kmalloc entry
 * @check:       hàm chính: nhận entry, trả về true = ACCEPT, false = DROP
 *               Gọi trong softirq context → KHÔNG được sleep, KHÔNG kmalloc
 * @init_entry:  khởi tạo state cho IP mới (gọi 1 lần khi tạo entry)
 * @list:        dùng nội bộ để link vào registry
 */
struct rl_plugin {
  const char *name;
  size_t entry_size;

  bool (*check)(struct rl_entry *e);
  void (*init_entry)(struct rl_entry *e);

  struct list_head list;
};

/**
 * struct rl_entry — header chung của mọi per-IP entry
 * Plugin nhúng struct này vào đầu state riêng của mình,
 * sau đó dùng container_of() để lấy state đầy đủ.
 *
 * @src_ip:    source IP (network byte order) — key của hashtable
 * @last_seen: jiffies lần cuối nhận packet — dùng cho TTL cleanup
 * @hnode:     hashtable node
 */
struct rl_entry {
  __be32 src_ip;
  unsigned long last_seen;
  struct hlist_node hnode;
};

/* Registry API — gọi từ plugin init/exit */
int rl_plugin_register(struct rl_plugin *p);
void rl_plugin_unregister(struct rl_plugin *p);

/* Lấy plugin đang active (NULL nếu chưa set) */
struct rl_plugin *rl_plugin_get_active(void);

/* Đổi plugin active theo tên — gọi từ /proc write handler */
int rl_plugin_set_active(const char *name);

#endif /* RL_PLUGIN_H */