#!/bin/bash

echo 512 > /proc/sys/vm/nr_hugepages

mkdir -p /mnt/huge
mount -t hugetlbfs none /mnt/huge