#!/bin/bash

ifconfig eth15 10.100.5.2
route add default gw 10.100.5.1
route add -net 10.20.5.0 netmask 255.255.255.0 gw 10.100.5.1