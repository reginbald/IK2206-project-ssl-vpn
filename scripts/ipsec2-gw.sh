#!/bin/bash

ifconfig eth17 192.168.20.5
route add default gw 192.168.20.1
ifconfig eth15 10.20.5.1
route add -net 10.20.5.0 netmask 255.255.255.0 gw 10.20.5.2
route add -net 10.100.5.0 netmask 255.255.255.0 gw 192.168.20.1