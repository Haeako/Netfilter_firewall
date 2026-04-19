#!/usr/bin/bash

sudo iptables -F

sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT
# accept loopback
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -N ANTIDOS
iptables -A INPUT -p tcp --syn -j ANTIDOS

iptables -A ANTIDOS -m hashlimit \
  --hashlimit 50/sec \
  --hashlimit-burst 100 \
  --hashlimit-mode srcip \
  --hashlimit-name per_ip_limit \
  -j RETURN

iptables -A ANTIDOS -m recent --name badguy --set -j DROP

iptables -A INPUT -m recent \
  --name badguy \
  --update --seconds 30 --hitcount 1 \
  -j DROP
