# Run this on host1
sudo ifconfig eth13 10.0.20.100
sudo route add -net 10.0.30.0 netmask 255.255.255.0 gw 10.0.20.1
sudo route add -host 10.0.5.10 gw 10.0.20.1

