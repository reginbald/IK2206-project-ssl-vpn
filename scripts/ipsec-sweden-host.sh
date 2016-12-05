#!/bin/bash

echo -n "Type eth# and hit [Enter] > "
read eth

sudo ifconfig $eth 10.100.5.100