# BPF ClusterIP Service 

> This is BPF code that demonstrates how to implement ClusterIP using BPF without modifying the applications. 



## load the BPF program

A simple bash script `load.sh` is included that performs the following tasks:

1. Compiles the sodk_xlate BPF code, using LLVM Clang frontend, that initializes the Service_Map and Backend_Map.
2. Uses bpftool to attach the above compiled code to the cgroup so that it gets invoked for all the socket operations such as connection established, etc. in the system.
3. Extracts the id of the Service_Map and Backend_Map created by the above program and pins the map to the virtual filesystem.

After running the script you should be able to verify the eBPF program is loaded in the kernel.

### Verifying BPF programs are loaded in the kernel

You can list all the BPF programs loaded and their map ids:

```bash
$ sudo bpftool prog show
...
142: cgroup_sock_addr  name sock4_connect  tag b28426c2c70dfac5  gpl
        loaded_at 2023-12-07T16:22:47+0800  uid 0
        xlated 4248B  jited 2582B  memlock 8192B  map_ids 47,45,46
        btf_id 162
```

You can also list all the BPF maps:

```bash
$ sudo bpftool map  
45: hash  name Service_Map  flags 0x0
        key 8B  value 92B  max_entries 256  memlock 28672B
        btf_id 162
46: hash  name Backend_Map  flags 0x0
        key 8B  value 16B  max_entries 256  memlock 8192B
        btf_id 162
47: array  name sock_xla.bss  flags 0x400
        key 4B  value 4B  max_entries 1  memlock 4096B
        btf_id 162
```


## Verifying BPF programs has been usable 

### Turn on tracing logs (if not enabled by default)
```bash
#echo 1 > /sys/kernel/debug/tracing/tracing_on
```

### use iperf3-client pod to connect the given ClusterIP(`Vip1` and `Vip2` in eBPF_Service.h) 
```bash
$ sudo kubectl exec -it iperf3-client-6f6b9d5fb5-xdnlv -- iperf3 -c 192.10.100.100 -i 2 -t 10
Connecting to host 192.10.100.100, port 5201
[  5] local 10.244.209.39 port 33432 connected to 10.244.105.222 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-2.01   sec  51.8 MBytes   216 Mbits/sec    0    803 KBytes
[  5]   2.01-4.01   sec   118 MBytes   492 Mbits/sec   26    865 KBytes
[  5]   4.01-6.03   sec   115 MBytes   477 Mbits/sec   90    951 KBytes
[  5]   6.03-8.01   sec   124 MBytes   527 Mbits/sec    0    980 KBytes
[  5]   8.01-10.02  sec  73.8 MBytes   308 Mbits/sec    0   1015 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.02  sec   482 MBytes   404 Mbits/sec  116             sender
[  5]   0.00-10.04  sec   482 MBytes   403 Mbits/sec                  receiver
```
The connect to Vip(192.10.100.100) has been redirect to one of the iperf3-server(10.244.105.222)

### Cat the kernel live streaming trace file: trace_pipe, in a shell to monitor the trace of the socket information through eBPF.
```bash
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
        sudo-91141   [000] d...1  5387.643552: bpf_trace_printk: Begin initialize the map!
        sudo-91141   [000] d...1  5387.643765: bpf_trace_printk: Success register service: virtual_svc1, IP: 10.96.96.96.
        sudo-91141   [000] d...1  5387.643771: bpf_trace_printk: Success register service: virtual_svc2, IP: 192.10.100.100.
        sudo-91141   [000] d...1  5387.643776: bpf_trace_printk: Success register backend(IP: 10.244.209.27) of service: virtual_svc1.
        sudo-91141   [000] d...1  5387.643780: bpf_trace_printk: Success register backend(IP: 10.244.105.222) of service: virtual_svc2.

        iperf3-116306  [001] d...1  6998.966686: bpf_trace_printk: Service 'virtual_svc2' exists,  IP: 192.10.100.100, has 1 backends.
        iperf3-116306  [001] d...1  6998.966753: bpf_trace_printk: Backend_pod IP: 10.244.105.222, Port: 5201, belongs to Service: virtual_svc2.

        iperf3-116306  [001] d...1  6999.027139: bpf_trace_printk: Service 'virtual_svc2' exists,  IP: 192.10.100.100, has 1 backends.
        iperf3-116306  [001] d...1  6999.027145: bpf_trace_printk: Backend_pod IP: 10.244.105.222, Port: 5201, belongs to Service: virtual_svc2.
```


## Cleanup

Running the `unload.sh` script detaches the eBPF programs from the hooks and unloads them from the kernel.

## Building

You can build on any Linux kernel with eBPF support. We have used Ubuntu Linux 22.04 with kernel 5.15.0-88-generic

### Ubuntu Linux

To prepare a Linux development environment for eBPF development, various packages and kernel headers need to be installed. Follow the following steps to prepare your development environment:
1. Prepare Ubuntu 22.04
2. Install the necessary tools
	```bash
	sudo apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl-dev bison flex graphviz iproute2
	```
3. Download the Linux kernel source
	1. You will need to update source URIs in /etc/apt/source.list
	2. Perform the following:
		```bash
		sudo apt-get update
		sudo apt-get source linux-image-$(uname -r)
		```
		If it fails to download the source, try:
		```bash
		sudo apt-get source linux-image-unsigned-$(uname -r)
		```
	3. More information on Ubuntu [wiki](https://wiki.ubuntu.com/Kernel/BuildYourOwnKernel)
4. Compile and install bpftool from source. It is not yet packaged as part of the standard distributions of Ubuntu. 
	```bash
	cd $kernel_src_dir/tools/bpf/bpftools
	make 
	make install.
	```
5. Dump the vmlinux into the directory sockredir 
	```bash
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > <program_path>/bpflet/ClusterIP/vmlinux.h
	```

6. You might also need to install libbfd-dev
