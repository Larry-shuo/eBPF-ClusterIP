#!/bin/bash

# enable debug output for each executed command
set -x

sudo rm "iperfpod_IP_Address.h"
# detach and unload the sock4_connect program
sudo bpftool cgroup detach "/sys/fs/cgroup/" connect4 pinned "/sys/fs/bpf/sock_xlate"
sleep 1

sudo rm "/sys/fs/bpf/sock_xlate"  
sleep 1

# delete maps
sudo rm "/sys/fs/bpf/Clusterip_svc_map"
sudo rm "/sys/fs/bpf/Backend_map"
sleep 1

