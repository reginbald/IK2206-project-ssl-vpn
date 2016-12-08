
#!/bin/bash

echo -n "Type eth# and hit [Enter] > "
read eth
echo -n "Type server IP address and hit [Enter] > "
read ip
# Run this on the gateway
sudo ifconfig $eth 10.0.20.1
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -p
sudo ./simpletun -i tun0 -c $ip -d
