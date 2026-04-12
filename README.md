# Hướng dẫn test firewall trên máy ảo

## 1. Chuẩn bị VM (Ubuntu 20.04 / 22.04)

```bash
# Cài kernel headers + công cụ build
sudo apt update
sudo apt install -y linux-headers-$(uname -r) build-essential hping3

# Xác nhận kernel headers khớp
ls /lib/modules/$(uname -r)/build
```

## 2. Build module

```bash
cd ~/firewall
make
# Kết quả: firewall.ko
```

## 3. Load module

```bash
sudo insmod firewall.ko
lsmod | grep firewall      # xác nhận đã load
dmesg | tail -5            # xem log khởi động
```

## 4. Kiểm tra /proc entries

```bash
cat /proc/firewall_config
cat /proc/firewall_stats
cat /proc/firewall_blacklist
cat /proc/firewall_whitelist
```

## 5. Chạy test script

```bash
chmod +x test_firewall.sh

# Test trên loopback (không cần 2 máy)
sudo ./test_firewall.sh lo

# Test cross-host (máy ảo 2 card mạng)
sudo ./test_firewall.sh eth0
```

---

## 6. Test thủ công từng tính năng

### Rate limit
```bash
# Đổi limit
echo "rate 50" | sudo tee /proc/firewall_config

# Xem config
cat /proc/firewall_config
# → rate_limit=50 pkt/s
```

### Blacklist
```bash
# Thêm IP
echo "add 192.168.1.100 attacker"   | sudo tee /proc/firewall_blacklist

# Sửa comment
echo "edit 192.168.1.100 confirmed" | sudo tee /proc/firewall_blacklist

# Xóa IP
echo "del 192.168.1.100"            | sudo tee /proc/firewall_blacklist

# Xóa tất cả
echo "flush x"                       | sudo tee /proc/firewall_blacklist

# Xem danh sách
cat /proc/firewall_blacklist
```

### Whitelist
```bash
echo "add 10.0.0.1 trusted-server" | sudo tee /proc/firewall_whitelist
echo "edit 10.0.0.1 gateway"       | sudo tee /proc/firewall_whitelist
echo "del 10.0.0.1"                 | sudo tee /proc/firewall_whitelist
cat /proc/firewall_whitelist
```

### DDoS simulation (hping3)
```bash
# Đặt limit thấp để dễ trigger
echo "rate 10" | sudo tee /proc/firewall_config

# Flood 500 SYN packet
sudo hping3 -S -p 80 --flood -c 500 127.0.0.1 -I lo

# Xem bao nhiêu bị drop
cat /proc/firewall_stats
# → dropped_ddos: <số lượng>
```

### Xem kernel log
```bash
# Realtime
sudo dmesg -wH | grep "fw:"

# Log gần đây
dmesg | grep "fw:" | tail -20
```

---

## 7. Setup 2 VM test cross-host

```
┌─────────────┐          ┌─────────────┐
│  VM Attacker│          │  VM Target  │
│  10.0.0.2   │──────────│  10.0.0.1   │
│             │ hping3 → │  (firewall) │
└─────────────┘          └─────────────┘
```

```bash
# Trên VM Target — load module
sudo insmod firewall.ko
echo "rate 30" | sudo tee /proc/firewall_config

# Trên VM Attacker — gửi flood
sudo hping3 -S -p 80 --flood -c 1000 10.0.0.1

# Trên VM Target — xem stats
watch -n 1 cat /proc/firewall_stats
```

---

## 8. Unload

```bash
sudo rmmod firewall
dmesg | tail -3   # "fw: unloaded"
```
