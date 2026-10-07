#!/bin/bash

set -e

echo "Configuring SW1 VLANs..."

# SW1 - USERS VLAN 10
sudo ovs-vsctl set port ovsp1 tag=10
sudo ovs-vsctl set port ovsp2 tag=10
sudo ovs-vsctl set port ovsp3 tag=10


echo "Configuring SW2 VLANs..."

# SW2 - SERVERS VLAN 20
sudo ovs-vsctl set port ovs2p1 tag=20
sudo ovs-vsctl set port ovs2p2 tag=20
sudo ovs-vsctl set port ovs2p3 tag=20
sudo ovs-vsctl set port ovs2p6 tag=20
# SW2 - DATABASE VLAN 30
sudo ovs-vsctl set port ovs2p4 tag=30
sudo ovs-vsctl set port ovs2p5 tag=30



echo "VLAN configuration completed."
