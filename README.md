# Thắt chặt hơn: chỉ cho 1 gói SYN mỗi giây
echo 1 > /sys/module/nf_antidos/parameters/rate_syn

# Nới lỏng: cho 1000 gói ICMP mỗi giây
echo 1000 > /sys/module/nf_antidos/parameters/rate_icmp

# Tăng thời gian ban lên 1 tiếng (3600 giây)
echo 3600 > /sys/module/nf_antidos/parameters/ban_sec