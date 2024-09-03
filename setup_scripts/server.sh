#!/bin/bash

sudo rmmod irdma

for i in {24..47}
do
  sudo echo 0 > /sys/devices/system/cpu/cpu$i/online
done

sudo ethtool -L ens19f0np0 combined 1
sudo ifconfig ens19f0np0 192.168.201.5/24

