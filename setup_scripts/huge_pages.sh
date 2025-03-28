#!/bin/bash

echo 16384 > /proc/sys/vm/nr_hugepages

mkdir -p /mnt/huge
mount -t hugetlbfs none /mnt/huge
