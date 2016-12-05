#!/bin/bash

echo -n "Type eth# and hit [Enter] > "
read eth
echo -n "Type client IP address and hit [Enter] > "
read ip
# Run this on the gateway
sudo ifconfig $eth 10.0.30.1
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -p
sudo ./simpletun -i tun0 -s $ip -d