#!/bin/bash

set -e

echo "Configuring SW1 VLANs..."

# SW1 - USERS VLAN 10
sudo ovs-vsctl set port ovsp1 tag=10
sudo ovs-vsctl set port ovsp2 tag=10
sudo ovs-vsctl set port ovsp3 tag=10
sudo ovs-vsctl set port ovsp4 tag=10


echo "Configuring SW2 VLANs..."

# SW2 - SERVERS VLAN 20
sudo ovs-vsctl set port ovs2p1 tag=20
sudo ovs-vsctl set port ovs2p3 tag=20
sudo ovs-vsctl set port ovs2p7 tag=20
# SW2 - APPLICATION VLAN 25
sudo ovs-vsctl set port ovs2p6 tag=25
# SW2 - MANAGEMENT VLAN 35
sudo ovs-vsctl set port ovs2p2 tag=35
sudo ovs-vsctl set port ovs2p11 tag=35
# SW2 - router uplinks for VLAN 25 and VLAN 35
sudo ovs-vsctl set port ovs2p12 tag=25
sudo ovs-vsctl set port ovs2p13 tag=35
# SW2 - DATABASE VLAN 30
sudo ovs-vsctl set port ovs2p4 tag=30
sudo ovs-vsctl set port ovs2p5 tag=30

# SW2 - IoT VLAN 40
sudo ovs-vsctl set port ovs2p8 tag=40
sudo ovs-vsctl set port ovs2p9 tag=40
sudo ovs-vsctl set port ovs2p10 tag=40

echo "Renewing DHCP clients after VLAN tags are applied..."
for node in pc1 pc2 iot1 iot2; do
    container="clab-step2-switch-${node}"
    docker exec "$container" sh -c '
        killall udhcpc 2>/dev/null || true
        ip addr flush dev eth1
        ip route flush dev eth1
        udhcpc -q -t 3 -T 5 -i eth1 >/var/log/udhcpc.log 2>&1 &
    '
done


echo "VLAN configuration completed."
