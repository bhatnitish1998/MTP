#!/bin/bash

for i in {12..47}
do
  sudo echo 0 > /sys/devices/system/cpu/cpu$i/online
done

sudo ethtool -L ens261f1 combined 1
sudo ifconfig ens261f1 192.168.201.5/24