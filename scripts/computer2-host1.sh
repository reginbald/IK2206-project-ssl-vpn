#!/bin/bash
# Run this on host1
sudo ifconfig eth13 10.0.30.100
sudo route add -net 10.0.20.0 netmask 255.255.255.0 gw 10.0.30.1
sudo route add -host 10.0.5.1 gw 10.0.20.1
