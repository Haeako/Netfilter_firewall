# Blacklist — thêm/xóa thủ công
echo "add 1.2.3.4" | sudo tee /proc/nf_antidos/banned
echo "del 192.168.2.18" | sudo tee /proc/nf_antidos/banned
cat /proc/nf_antidos/banned        # xem danh sách + TTL còn lại

# Whitelist — thêm/xóa thủ công
echo "add 192.168.2.18" | sudo tee /proc/nf_antidos/whitelist
echo "del 192.168.2.18" | sudo tee /proc/nf_antidos/whitelist
cat /proc/nf_antidos/whitelist     # xem danh sách
