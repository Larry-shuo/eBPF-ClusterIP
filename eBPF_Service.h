#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"

#define MAX_ENTRIES 256
#define MAX_BACKENS 8

#define CONNECT_REJECT	0
#define CONNECT_PROCEED	1

#ifndef FORCE_READ
#define FORCE_READ(X) (*(volatile typeof(X) *)&X)
#endif

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...) \
    (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#ifndef printk
#define printk(fmt, ...)                                       \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

/* ebpf helper function
 * The generated function is used for parameter verification
 * by the eBPF verifier
 */
static void  *BPF_FUNC(map_lookup_elem, void *map, const void *key);
static void  BPF_FUNC(map_update_elem, void *map, const void *key, const void *value, __u32 flags);
static void  BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);
static __u32 BPF_FUNC(get_prandom_u32);
static long  BPF_FUNC(probe_read_user_str, void *dst, u32 size, const void *unsafe_ptr);
static long  BPF_FUNC(probe_read, void *dst, u32 size, const void *unsafe_ptr);


// Virtual IPs
static const __u32 Vip1 = 10 + (96 << 8) + (96 << 16) + (96 << 24);     // 10.96.96.96
static const __u32 Vip2 = 192 + (10 << 8) + (100 << 16) + (100 << 24); // 192.10.100.100
static const __u16 clusterip_port = 5201;

static const __u16 iperf_pod_port = 5201;


// All IP addresses and ports stored in network byte order
struct sock_key
{
    __u32 dip4;     // destination IP
    __u16 dport;    // destination port
};

struct Clusterip_Service
{
    __u32 vip4;             // Service virtual IPv4 address
    __u16 port;
    char service_name[16];  // the name of Service, stored in 16 chars
    struct sock_key backend_key[MAX_BACKENS];   // the set of its backends
    __u16 count;             // the number of service's endpoints.
    __u8 proto;
};

struct backend_pod
{
    __u32 ip4;
    __u16 port;
    __u8 proto;
    __u32 service_vip4;
    __u16 service_port;
};

// BPF Map definition
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock_key);
    __type(value, struct Clusterip_Service);
    __uint(max_entries, MAX_ENTRIES);
    __uint(map_flags, 0);
} Service_Map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock_key); // key为pod ip
    __type(value, struct backend_pod);
    __uint(max_entries, MAX_ENTRIES);
    __uint(map_flags, 0);
} Backend_Map SEC(".maps");