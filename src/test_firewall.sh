#!/usr/bin/env bash
# test_firewall.sh — Kiểm tra firewall module trên máy ảo
# Yêu cầu: module đã được load (sudo insmod firewall.ko)
# Dùng hping3 để sinh traffic DDoS giả lập

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

IFACE="${1:-lo}"        # interface để test, mặc định loopback
TARGET_IP="127.0.0.1"  # đổi thành IP VM đích nếu test cross-host

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

check_deps() {
    info "Kiểm tra dependencies..."
    local missing=0
    for cmd in hping3 iptables cat grep; do
        if ! command -v "$cmd" &>/dev/null; then
            warn "Thiếu: $cmd"
            missing=$((missing+1))
        fi
    done
    [ $missing -eq 0 ] && pass "Tất cả dependencies có mặt" \
                       || fail "$missing công cụ còn thiếu — cài: sudo apt install hping3"
}

check_module() {
    info "Kiểm tra module..."
    if lsmod | grep -q "^firewall"; then
        pass "Module đang chạy"
    else
        fail "Module chưa load — chạy: sudo insmod firewall.ko"
        exit 1
    fi

    for f in firewall_config firewall_stats firewall_blacklist firewall_whitelist; do
        if [ -f "/proc/$f" ]; then
            pass "/proc/$f tồn tại"
        else
            fail "/proc/$f KHÔNG tồn tại"
        fi
    done
}

show_stats() {
    echo ""
    info "=== Stats hiện tại ==="
    cat /proc/firewall_stats
    echo ""
}

# ─────────────────────────────────────────
# TEST 1: Đọc / ghi config
# ─────────────────────────────────────────
test_config() {
    info "── TEST 1: Config rate limit ──"

    # Đọc giá trị hiện tại
    CURRENT=$(cat /proc/firewall_config | grep -oP '(?<=rate_limit=)\d+')
    info "Rate limit hiện tại: $CURRENT pkt/s"

    # Đổi sang 50
    echo "rate 50" | sudo tee /proc/firewall_config > /dev/null
    NEW=$(cat /proc/firewall_config | grep -oP '(?<=rate_limit=)\d+')
    [ "$NEW" = "50" ] && pass "Ghi rate_limit=50 thành công" \
                       || fail "Ghi rate_limit thất bại (got $NEW)"

    # Đổi lại 200
    echo "rate 200" | sudo tee /proc/firewall_config > /dev/null
    pass "Reset rate_limit=200"

    # Test giá trị không hợp lệ
    echo "rate 0"   | sudo tee /proc/firewall_config > /dev/null 2>&1 || true
    echo "rate abc" | sudo tee /proc/firewall_config > /dev/null 2>&1 || true
    STILL=$(cat /proc/firewall_config | grep -oP '(?<=rate_limit=)\d+')
    [ "$STILL" = "200" ] && pass "Invalid input bị từ chối" \
                          || fail "Invalid input không bị từ chối"
}

# ─────────────────────────────────────────
# TEST 2: Blacklist CRUD
# ─────────────────────────────────────────
test_blacklist() {
    info "── TEST 2: Blacklist CRUD ──"

    BL=/proc/firewall_blacklist

    # add
    echo "add 10.0.0.1 attacker-test" | sudo tee $BL > /dev/null
    grep -q "10.0.0.1" $BL && pass "add 10.0.0.1 OK" || fail "add thất bại"

    # duplicate (phải im lặng, không báo lỗi)
    echo "add 10.0.0.1 duplicate" | sudo tee $BL > /dev/null
    COUNT=$(grep -c "10.0.0.1" $BL)
    [ "$COUNT" -eq 1 ] && pass "Duplicate bị bỏ qua" || fail "Duplicate được chèn"

    # add thêm vài IP
    echo "add 10.0.0.2 attacker-2" | sudo tee $BL > /dev/null
    echo "add 10.0.0.3 scanner"    | sudo tee $BL > /dev/null

    # edit comment
    echo "edit 10.0.0.1 updated-comment" | sudo tee $BL > /dev/null
    grep -q "updated-comment" $BL && pass "edit comment OK" || fail "edit thất bại"

    # del
    echo "del 10.0.0.2" | sudo tee $BL > /dev/null
    grep -q "10.0.0.2" $BL && fail "del thất bại" || pass "del 10.0.0.2 OK"

    # flush
    echo "flush x" | sudo tee $BL > /dev/null
    grep -q "empty" $BL && pass "flush OK" || fail "flush thất bại"

    info "Blacklist sau test:"
    cat $BL
}

# ─────────────────────────────────────────
# TEST 3: Whitelist CRUD
# ─────────────────────────────────────────
test_whitelist() {
    info "── TEST 3: Whitelist CRUD ──"

    WL=/proc/firewall_whitelist

    echo "add 192.168.1.1 trusted-gw"   | sudo tee $WL > /dev/null
    echo "add 192.168.1.2 monitor"      | sudo tee $WL > /dev/null
    grep -q "192.168.1.1" $WL && pass "add whitelist OK" || fail "add whitelist thất bại"

    echo "edit 192.168.1.1 gateway-main" | sudo tee $WL > /dev/null
    grep -q "gateway-main" $WL && pass "edit whitelist OK" || fail "edit whitelist thất bại"

    echo "del 192.168.1.2" | sudo tee $WL > /dev/null
    grep -q "192.168.1.2" $WL && fail "del whitelist thất bại" || pass "del whitelist OK"

    echo "flush x" | sudo tee $WL > /dev/null
    pass "flush whitelist OK"
}

# ─────────────────────────────────────────
# TEST 4: DDoS rate limiting (hping3)
# ─────────────────────────────────────────
test_ddos() {
    info "── TEST 4: DDoS sliding window ──"

    if ! command -v hping3 &>/dev/null; then
        warn "hping3 không có — bỏ qua test DDoS thực"
        warn "Cài: sudo apt install hping3"
        return
    fi

    # Đặt rate_limit thấp để test dễ trigger
    echo "rate 20" | sudo tee /proc/firewall_config > /dev/null
    info "rate_limit = 20 pkt/s"

    BEFORE=$(cat /proc/firewall_stats | grep dropped_ddos | grep -oP '\d+$')
    info "dropped_ddos trước: $BEFORE"

    # Gửi 100 packet nhanh vào loopback — nên trigger rate limit
    info "Gửi 100 SYN packet nhanh tới $TARGET_IP..."
    sudo hping3 -S -p 80 --flood -c 100 $TARGET_IP -I $IFACE \
        --quiet 2>/dev/null || true
    sleep 1  # để hook xử lý xong

    AFTER=$(cat /proc/firewall_stats | grep dropped_ddos | grep -oP '\d+$')
    info "dropped_ddos sau: $AFTER"

    if [ "$AFTER" -gt "$BEFORE" ]; then
        pass "DDoS rate limiting hoạt động (dropped $((AFTER - BEFORE)) packets)"
    else
        fail "Không có packet nào bị drop — kiểm tra interface '$IFACE'"
    fi

    # Khôi phục rate limit
    echo "rate 100" | sudo tee /proc/firewall_config > /dev/null
    info "Khôi phục rate_limit = 100 pkt/s"
}

# ─────────────────────────────────────────
# TEST 5: Blacklist block thực sự
# ─────────────────────────────────────────
test_blacklist_block() {
    info "── TEST 5: Blacklist block packet ──"

    if ! command -v hping3 &>/dev/null; then
        warn "hping3 không có — bỏ qua"
        return
    fi

    # Lấy IP của interface test
    SRC_IP=$(ip -4 addr show $IFACE | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
    if [ -z "$SRC_IP" ]; then
        warn "Không lấy được IP của $IFACE"
        return
    fi

    info "Blacklist IP nguồn: $SRC_IP"
    echo "add $SRC_IP test-block" | sudo tee /proc/firewall_blacklist > /dev/null

    BEFORE=$(cat /proc/firewall_stats | grep dropped_blacklist | grep -oP '\d+$')
    sudo hping3 -S -p 80 -c 10 $TARGET_IP -I $IFACE --quiet 2>/dev/null || true
    sleep 0.5
    AFTER=$(cat /proc/firewall_stats | grep dropped_blacklist | grep -oP '\d+$')

    if [ "$AFTER" -gt "$BEFORE" ]; then
        pass "Blacklist block hoạt động (dropped $((AFTER - BEFORE)) packets)"
    else
        fail "Blacklist không block được packet"
    fi

    # Xóa khỏi blacklist
    echo "del $SRC_IP" | sudo tee /proc/firewall_blacklist > /dev/null
    pass "Xóa $SRC_IP khỏi blacklist"
}

# ─────────────────────────────────────────
# TEST 6: Whitelist bypass rate limit
# ─────────────────────────────────────────
test_whitelist_bypass() {
    info "── TEST 6: Whitelist bypass rate limit ──"

    if ! command -v hping3 &>/dev/null; then
        warn "hping3 không có — bỏ qua"
        return
    fi

    SRC_IP=$(ip -4 addr show $IFACE | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
    if [ -z "$SRC_IP" ]; then warn "Không lấy được IP"; return; fi

    echo "rate 5"              | sudo tee /proc/firewall_config    > /dev/null
    echo "add $SRC_IP trusted" | sudo tee /proc/firewall_whitelist > /dev/null

    DDOS_BEFORE=$(cat /proc/firewall_stats | grep dropped_ddos | grep -oP '\d+$')
    WL_BEFORE=$(cat /proc/firewall_stats | grep whitelisted | grep -oP '\d+$')

    sudo hping3 -S -p 80 -c 50 $TARGET_IP -I $IFACE --quiet 2>/dev/null || true
    sleep 0.5

    DDOS_AFTER=$(cat /proc/firewall_stats | grep dropped_ddos | grep -oP '\d+$')
    WL_AFTER=$(cat /proc/firewall_stats | grep whitelisted | grep -oP '\d+$')

    [ "$DDOS_AFTER" -eq "$DDOS_BEFORE" ] \
        && pass "Whitelist IP không bị rate-limit" \
        || fail "Whitelist IP vẫn bị rate-limit"

    [ "$WL_AFTER" -gt "$WL_BEFORE" ] \
        && pass "Counter whitelisted tăng: $((WL_AFTER - WL_BEFORE)) packets" \
        || fail "Counter whitelisted không tăng"

    echo "flush x"  | sudo tee /proc/firewall_whitelist > /dev/null
    echo "rate 100" | sudo tee /proc/firewall_config    > /dev/null
}

# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Firewall Module Test Suite v2.0   ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""
info "Interface: $IFACE   Target: $TARGET_IP"
echo ""

check_deps
check_module
show_stats

test_config
test_blacklist
test_whitelist
test_ddos
test_blacklist_block
test_whitelist_bypass

echo ""
info "=== Stats cuối ==="
show_stats
echo -e "${GREEN}╔══════════════════════════════╗${NC}"
echo -e "${GREEN}║   Tất cả test đã chạy xong  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════╝${NC}"
