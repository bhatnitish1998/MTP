#!/bin/bash

# disable hyperthreading, set combined 1, setup ip address.
cd nitish/MTP/setup_scripts
sudo ./server.sh 

# disable interrupts in busy poll
echo 200000 |sudo tee  /sys/class/net/ens19f0np0/gro_flush_timeout
echo 2 |sudo tee  /sys/class/net/ens19f0np0/napi_defer_hard_irqs  
