#!/bin/bash

# enable debug output for each executed command
set -x

# exit if any command fails
set -e

# Mount the bpf filesystem when it not exist
bpf_mounted=$(mount | grep -c "sys/fs/bpf")

if [ $bpf_mounted -eq 0 ]; then
    sudo mount -t bpf bpf /sys/fs/bpf/
fi

# Obtain the pod IP and write into header
clang get_iperfpod_ip.c -o get_iperfpod_ip

./get_iperfpod_ip

# Compile the bpf_sockops program
clang -O2 -g -target bpf -c sock_xlate.c -o sock_xlate.o

# Load and attach the bpf_sockops program
sudo bpftool prog load sock_xlate.o "/sys/fs/bpf/sock_xlate"
# get the cgroup filesystem path
cgroup_path=$(mount | grep 'cgroup' | awk 'NR==1{print $3}' )
sudo bpftool cgroup attach "$cgroup_path" connect4 pinned "/sys/fs/bpf/sock_xlate"

# find maps and pin maps
MAP_IDs=$(sudo bpftool prog show pinned "/sys/fs/bpf/sock_xlate"| grep -o -E 'map_ids [0-9]+,[0-9]+,[0-9]+' | cut -d ' ' -f2)
MAP_ID1=$(echo $MAP_IDs | cut -d ',' -f1)
MAP_ID2=$(echo $MAP_IDs | cut -d ',' -f2)
MAP_ID3=$(echo $MAP_IDs | cut -d ',' -f3)


sudo bpftool map pin id $MAP_ID1 "/sys/fs/bpf/Clusterip_svc_map"
sudo bpftool map pin id $MAP_ID2 "/sys/fs/bpf/Backend_map"