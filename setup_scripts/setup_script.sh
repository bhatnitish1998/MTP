#!/bin/bash

sudo rmmod irdma

sudo ethtool -L <interface> combined 1
sudo ifconfig <interface> 192.168.201.5/24

echo 16384 > /proc/sys/vm/nr_hugepages

mkdir -p /mnt/huge
mount -t hugetlbfs none /mnt/huge
