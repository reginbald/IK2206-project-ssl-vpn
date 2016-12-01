# Run this on the gateway
sudo ifconfig eth15 10.0.20.1
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -p
sudo ./simpletun-udp -i tun0 -c 130.229.172.67 -d

