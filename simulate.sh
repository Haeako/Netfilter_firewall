# 1. Biên dịch và cài đặt
echo "[*] Compiling module..."
make
sudo insmod token_bucket_mod.ko

# 2. Kiểm tra trạng thái ban đầu
echo "[*] Initial config:"
cat /proc/token_bucket_config

# 3. Chạy Flood Test với hping3 (Mô phỏng traffic dồn dập)
# -1: Chế độ ICMP (giống ping)
# -c 50: Gửi 50 gói
# --fast: Gửi 10 gói mỗi giây (hoặc dùng --flood để gửi nhanh nhất có thể)
echo "[*] Sending 50 ICMP packets fast (10 pkts/sec)..."
sudo hping3 -1 -c 50 -i u100000 127.0.0.1 --quiet

# 4. Cập nhật thông số qua file /proc
# Giới hạn cực thấp: 1 gói/giây, dung lượng bucket là 2
echo "[*] Updating config to Rate=1, Capacity=2..."
echo "1 2" | sudo tee /proc/token_bucket_config

# 5. Kiểm tra lại với cấu hình mới bằng hping3
# Gửi 10 gói, mỗi gói cách nhau 0.2 giây (-i u200000)
# Với Rate=1, chắc chắn sẽ thấy mất gói (packet loss) rất cao
echo "[*] Sending 10 packets with new config (Rate=1, Cap=2)..."
sudo hping3 -1 -c 10 -i u200000 127.0.0.1

# 6. Gỡ module
echo "[*] Cleaning up..."
sudo rmmod token_bucket_mod
make clean

echo "[*] Kernel logs (dmesg):"
dmesg | tail -n 20