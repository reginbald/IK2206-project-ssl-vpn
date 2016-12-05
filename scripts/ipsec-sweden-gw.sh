#!/bin/bash

echo -n "Type eth# and hit [Enter] > "
read eth

sudo ifconfig $eth 10.100.5.1
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -p

ipsec pki --pub --in private/ClientKey.pem --type rsa | \
	ipsec pki --issue --lifetime 730 \
	--cacert cacerts/strongswanCert.pem \
	--cakey private/strongswanKey.pem \
	--dn "C=UK, O=strongSwan, CN=client@kth.uk" \
	--san client@kth.uk \
	--outform pem > certs/CLientCert.pem


iptables -t nat -A POSTROUTING -o eth14 ! -p esp -j SNAT --to-source 10.0.2.4

sudo route add -net 10.20.5.0 netmask 255.255.255.0 gw 10.0.5.1

#https://www.zeitgeist.se/2013/11/22/strongswan-howto-create-your-own-vpn/
