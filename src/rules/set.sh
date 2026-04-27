#!/usr/bin/bash
if [[ $EUID -ne 0 ]]; then echo "sudo bash $0"; exit 1; fi

iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 1. Loopback
iptables -A INPUT -i lo -j ACCEPT

# 2. INVALID
iptables -A INPUT -m conntrack \
  --ctstate INVALID -j DROP

# 3. Rate limit TRƯỚC ESTABLISHED
#    Vượt 100/sec per srcip → SET badguy
iptables -A INPUT -m hashlimit \
  --hashlimit-above 100/sec \
  --hashlimit-burst 200 \
  --hashlimit-mode srcip \
  --hashlimit-name rate_limit \
  -m recent --name badguy --set

# 4. DROP IP trong badguy (--update refresh timer)
iptables -A INPUT -m recent \
  --name badguy \
  --update --seconds 30 \
  -j LOG --log-prefix "[BADGUY-DROP] " --log-level 4

iptables -A INPUT -m recent \
  --name badguy \
  --update --seconds 30 \
  -j DROP

# 5. ESTABLISHED/RELATED sau rate limit
iptables -A INPUT -m conntrack \
  --ctstate ESTABLISHED,RELATED -j ACCEPT

# 6. ACCEPT còn lại
iptables -A INPUT -j ACCEPT

echo "✅ Done"
iptables -nvL INPUT --line-numbers
