# Netfilter Firewall - nf_antidos Module

**Một module kernel Linux stateless để phòng chống tấn công DoS (Denial of Service) sử dụng Netfilter framework.**

> **Phiên bản:** 1.5 (Removed WEB filtering)  
> **Giấy phép:** GPL-2.0  
> **Ngôn ngữ:** C (Linux Kernel Module)

---

## 📋 Tổng Quan

Module `nf_antidos` là một firewall stateless hoạt động tại kernel space để bảo vệ hệ thống khỏi các tấn công DoS bằng cách giới hạn tốc độ (rate limiting) các gói tin SYN và ICMP. Nó sử dụng:

- **Token Bucket Algorithm** để kiểm soát luồng dữ liệu
- **Hash Table** để lưu trữ thông tin các IP
- **Netfilter Framework** để chặn gói tin tại PRE_ROUTING hook
- **Proc Filesystem** để cung cấp giao diện quản lý

---

## ⚙️ Tính Năng Chính

### 1. **Giới Hạn Tốc Độ (Rate Limiting)**
   - Kiểm soát gói **SYN** TCP
   - Kiểm soát gói **ICMP** Echo Request
   - Cấu hình tốc độ độc lập cho mỗi loại gói tin

### 2. **Token Bucket Algorithm**
   - Cho phép tối đa (burst) gói tin vượt quá tốc độ trong thời gian ngắn
   - Tự động cộng thêm tokens theo thời gian
   - Tính toán dựa trên jiffies (clock ticks của kernel)

### 5. **Thống Kê Thời Gian Thực**
   - Số gói tin được chấp nhận
   - Số gói tin bị hủy
   - Số lần cấm tự động
   - Số lượng entries hiện tại

---

## 🏗️ Kiến Trúc

### Cấu Trúc Dữ Liệu

```c
struct dos_entry {
    __be32 src_ip;                // IP nguồn
    unsigned long last_seen;      // Thời điểm cuối cùng nhìn thấy
    unsigned long ban_until;      // Thời gian cấm kết thúc
    
    unsigned long last_refill_syn;  // Lần cuối cộng SYN tokens
    unsigned long last_refill_icmp; // Lần cuối cộng ICMP tokens
    
    uint32_t tokens_syn;          // Tokens SYN còn lại
    uint32_t tokens_icmp;         // Tokens ICMP còn lại
    
    struct hlist_node hnode;      // Node trong hash table
};
