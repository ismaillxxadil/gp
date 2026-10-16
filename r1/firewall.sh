#!/bin/sh

set -eu

iptables -F FORWARD
iptables -X R1-FORWARD 2>/dev/null || true
iptables -N R1-FORWARD
iptables -A FORWARD -j R1-FORWARD

iptables -A R1-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Users may reach the frontend and the explicitly supported management services.
iptables -A R1-FORWARD -s 10.10.10.0/24 -d 10.10.20.20/32 \
    -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A R1-FORWARD -s 10.10.10.0/24 -d 10.10.35.10/32 \
    -p tcp --dport 22 -j ACCEPT
iptables -A R1-FORWARD -s 10.10.10.0/24 -d 10.10.35.40/32 \
    -p tcp --dport 445 -j ACCEPT

# The application path is WEB1 -> APP1 -> DB1.
iptables -A R1-FORWARD -s 10.10.20.20/32 -d 10.10.25.30/32 \
    -p tcp --dport 3000 -j ACCEPT
iptables -A R1-FORWARD -s 10.10.25.30/32 -d 10.10.30.10/32 \
    -p tcp --dport 5432 -j ACCEPT

# Record denied routed traffic without flooding the logs.
iptables -A R1-FORWARD -m limit --limit 6/min --limit-burst 10 \
    -j LOG --log-prefix "R1-FW-DROP " --log-level 4
iptables -A R1-FORWARD -j DROP

iptables -P FORWARD DROP
