#!/bin/bash
# Run this on the gateway

sudo ip addr add 10.0.5.1/24 dev tun0
sudo ifconfig tun0 up
sudo route add -net 10.0.30.0 netmask 255.255.255.0 gw 10.0.5.1
