#!/bin/bash

set -e

echo "=== 1. Rebuilding Containerlab ==="
sudo containerlab destroy -t step2.clab.yml -c
sudo containerlab deploy -t step2.clab.yml

echo "=== 2. Applying VLAN Configuration ==="
bash config/vlan-config.sh

echo "=== 3. Configuring OVS SPAN Mirror ==="
sudo ovs-vsctl clear bridge sw2 mirrors
sudo ovs-vsctl -- --id=@p get port ovs2p_probe \
  -- --id=@m create mirror name=span select-all=true output-port=@p \
  -- set bridge sw2 mirrors=@m
sudo ovs-vsctl clear bridge sw1 mirrors
sudo ovs-vsctl -- --id=@p get port ovsp_probe \
  -- --id=@m create mirror name=span-sw1 select-all=true output-port=@p \
  -- set bridge sw1 mirrors=@m
  
echo "=== Lab successfully deployed with active NOTLINE monitoring! ==="
