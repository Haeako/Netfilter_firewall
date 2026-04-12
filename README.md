# nf_antidos

Anti-DoS Linux kernel module dùng Netfilter — kiến trúc plugin cho phép swap thuật toán rate-limiting lúc runtime.

## Tổng quan

```
Packet in
    │
    ▼
[Layer 1] Blacklist check      ← O(1) hashtable, DROP ngay nếu bị ban
    │
    ▼
[Layer 2] Connection limit     ← đếm conn đồng thời per IP
    │
    ▼
[Layer 3] Rate limit plugin    ← swap được qua /proc (Token/Leaky/Fixed Window)
    │
    ▼
[Layer 4] Auto-ban             ← violation ≥ threshold → ban IP với TTL
    │
    ▼
NF_ACCEPT
```

Hook duy nhất: `NF_INET_PRE_ROUTING` — drop sớm nhất có thể, trước routing decision.

---

## Cấu trúc

```
nf_antidos/
├── Makefile
├── core/
│   └── nf_antidos.c       # pipeline chính, blacklist, conn limit, auto-ban, /proc
└── plugins/
│   ├── rl_plugin.h        # vtable interface
│   ├── tb_plugin.c        # Token Bucket
│   ├── lb_plugin.c        # Leaky Bucket
│   └── fw_plugin.c        # Fixed Window Counter
└── tests/
    ├── test_logic.c       # unit test thuần C — không cần kernel
    ├── test_runner.sh     # integration test trong VM
    └── debug.sh           # ftrace / kprobe / live stats toolkit
```

---

## Build & Load

```bash
# Cài kernel headers
sudo apt install linux-headers-$(uname -r)

# Build tất cả module
make

# Load (core trước, plugin sau)
make load

# Xem plugin đang active
cat /proc/nf_antidos/plugin
```

---

## /proc interface

| File | Quyền | Mô tả |
|---|---|---|
| `/proc/nf_antidos/plugin` | rw | đọc/ghi tên plugin active |
| `/proc/nf_antidos/stats` | r | counter accept/drop |
| `/proc/nf_antidos/banned` | r | danh sách IP đang bị ban + TTL |

### Swap plugin runtime

```bash
echo "token_bucket" | sudo tee /proc/nf_antidos/plugin
echo "leaky_bucket" | sudo tee /proc/nf_antidos/plugin
echo "fixed_window" | sudo tee /proc/nf_antidos/plugin
```

### Xem stats

```bash
cat /proc/nf_antidos/stats
# accepted:    1024
# drop_bl:     312     ← blacklist
# drop_conn:   88      ← connection limit
# drop_rl:     540     ← rate limit
# auto_bans:   3
```

---

## Tham số module

Truyền khi `insmod` hoặc chỉnh runtime qua `/sys/module/`:

| Tham số | Mặc định | Mô tả |
|---|---|---|
| `max_conn_per_ip` | 20 | số connection tối đa per IP |
| `ban_threshold` | 5 | số violation trước khi ban |
| `ban_ttl_sec` | 300 | giây IP bị ban |
| `entry_ttl_sec` | 120 | giây xóa entry không dùng |

```bash
sudo insmod nf_antidos.ko max_conn_per_ip=50 ban_threshold=10 ban_ttl_sec=600

# Hoặc chỉnh runtime:
echo 50 | sudo tee /sys/module/nf_antidos/parameters/max_conn_per_ip
```

---

## So sánh plugin

| | Token Bucket | Leaky Bucket | Fixed Window |
|---|---|---|---|
| Bộ nhớ / IP | ~24 bytes | ~24 bytes | ~24 bytes |
| CPU / packet | O(1) | O(1) | O(1) |
| Burst hợp lệ | **Có** | Không | Không |
| Smoothing | Không | **Có** | Không |
| Boundary burst | Không | Không | **Có** (known) |
| Phù hợp | General DoS | Traffic smooth | Đơn giản nhất |

---

## Plugin mới

Implement `struct rl_plugin` trong `plugins/rl_plugin.h`:

```c
struct my_entry {
    struct rl_entry base;   /* PHẢI ở đầu */
    /* state riêng */
};

static bool my_check(struct rl_entry *e) {
    struct my_entry *me = container_of(e, struct my_entry, base);
    /* logic của bạn — không được sleep, không kmalloc */
    return true; /* ACCEPT */ /* false = DROP */
}

static struct rl_plugin my_plugin = {
    .name       = "my_algo",
    .entry_size = sizeof(struct my_entry),
    .check      = my_check,
    .init_entry = my_init,
};

module_init → rl_plugin_register(&my_plugin);
module_exit  → rl_plugin_unregister(&my_plugin);
```

---

## Test

### Tầng 1 — Unit test (không cần kernel)

```bash
gcc -o test_logic tests/test_logic.c && ./test_logic
```

Stub kernel types, fake `jiffies` để điều khiển thời gian — chạy được trên bất kỳ máy Linux nào.

### Tầng 2 — Integration test (cần VM + module loaded)

```bash
sudo apt install hping3
sudo bash tests/test_runner.sh [TARGET_IP]
```

### Tầng 3 — Debug runtime

```bash
# 3 terminal:
sudo bash tests/debug.sh live          # live stats
sudo bash tests/debug.sh dmesg         # kernel log
hping3 -S -p 80 --faster -c 500 TARGET # traffic

# Các lệnh khác:
sudo bash tests/debug.sh ftrace_start  # trace hook
sudo bash tests/debug.sh ftrace_stop
sudo bash tests/debug.sh kprobe_ban    # probe bl_ban_ip
sudo bash tests/debug.sh snapshot      # dump state ra file
```

---

## Unload

```bash
make unload
# hoặc thủ công (plugin trước, core sau):
sudo rmmod fw_plugin lb_plugin tb_plugin
sudo rmmod nf_antidos
```

---

## Lưu ý

- **Luôn test trong VM trước** — kernel panic có thể corrupt filesystem.
- Hook ở `PRE_ROUTING` — đủ cho anti-DoS inbound, không cần thêm hook khác.
- UDP amplification flood (DNS/NTP reflection) cần chặn ở edge/carrier, không xử lý được ở đây.
- Không thay thế hardware firewall với multi-Gbit/s attack.
