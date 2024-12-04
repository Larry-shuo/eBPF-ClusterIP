#include "vmlinux.h"
#include "eBPF_Service.h"
#include "iperfpod_IP_Address.h"

char ____license[] SEC("license") = "GPL";

int map_is_init = 0;

static void inline
register_service(struct Clusterip_Service *svc)
{
    struct sock_key key = {};
    key.dip4 = svc->vip4;
    key.dport = svc->port;

    struct Clusterip_Service *tsvc;
    tsvc = map_lookup_elem(&Service_Map, &key);
    if (!tsvc)
    {
        map_update_elem(&Service_Map, &key, svc, BPF_ANY);
        printk("Success register service: %s, IP: %pI4.", svc->service_name, &svc->vip4);
    }
}


static void inline
register_backend(struct backend_pod *backend)
{
    struct sock_key pod_key = {}; 
    pod_key.dip4 = backend->ip4;
    pod_key.dport = backend->port;

    // check the backend before register
    struct backend_pod *tbackend;
    tbackend = map_lookup_elem(&Backend_Map, &pod_key);
    if(tbackend) // backend has existed.
        return;

    // find the corresponding service
    struct sock_key svc_key = {};
    svc_key.dip4 = backend->service_vip4;
    svc_key.dport = backend->service_port;

    struct Clusterip_Service *svc;
    svc = map_lookup_elem(&Service_Map, &svc_key);
    if (!svc){
        return;
    }
    // the service exists.
    for(int i = 0; i < MAX_BACKENS; i++)
    {
        if(svc->backend_key[i].dip4 == 0){
            svc->backend_key[i] = pod_key;
            svc->count++;
            map_update_elem(&Backend_Map, &pod_key, backend, BPF_ANY);
            printk("Success register backend(IP: %pI4) of service: %s.", 
                    &backend->ip4, &svc->service_name);
            break;
        }
    }
}


static void inline
map_init()
{
    printk("Begin initialize the map!");

    // define virtual_svc and its key
    struct Clusterip_Service virtual_svc1 = {};
    virtual_svc1.vip4 = Vip1;
    virtual_svc1.port = bpf_htons(clusterip_port);
    virtual_svc1.count = 0;
    __builtin_memcpy(virtual_svc1.service_name, "virtual_svc1", sizeof(virtual_svc1.service_name));

    struct Clusterip_Service virtual_svc2 = {};
    virtual_svc2.vip4 = Vip2;
    virtual_svc2.port = bpf_htons(clusterip_port);
    virtual_svc2.count = 0;
    __builtin_memcpy(virtual_svc2.service_name, "virtual_svc2", sizeof(virtual_svc2.service_name));

    // register services
    register_service(&virtual_svc1);
    register_service(&virtual_svc2);

    struct backend_pod backend1 = {};
    backend1.service_vip4 = virtual_svc1.vip4;
    backend1.service_port = virtual_svc1.port;
    backend1.ip4 = pod1_ip;
    backend1.port = bpf_htons(iperf_pod_port);

    struct backend_pod backend2 = {};
    backend2.service_vip4 = virtual_svc2.vip4;
    backend2.service_port = virtual_svc2.port;
    backend2.ip4 = pod2_ip;
    backend2.port = bpf_htons(iperf_pod_port);

    // register backends
    register_backend(&backend1);
    register_backend(&backend2);

    map_is_init=1;
}


static struct sock_key inline lookup_random_pod(struct Clusterip_Service *svc)
{
    __u32 randomindex = get_prandom_u32() % svc->count % MAX_BACKENS;
    return svc->backend_key[randomindex];
}


static int
__sock4_xlate_fwd(struct bpf_sock_addr *ctx)
{
    struct Clusterip_Service *svc;
    struct sock_key dkey = {};
    dkey.dip4 = ctx->user_ip4;
    dkey.dport = ctx->user_port;
    // printk("sock message: dip: %pI4, dport: %u.", 
    //         &dkey.dip4, bpf_ntohs(dkey.dport));
    
    svc = map_lookup_elem(&Service_Map, &dkey);
    if (!svc){
        // printk("The IP(%pI4) hasn't Service!\n", &dkey.dip4);
        return 0;
    }
    else if(svc->count == 0){
        printk("Service('%s') has no backend!\n", svc->service_name);
        return 0;
    }

    // service exists and has corresponding backends
    else {
        printk("Service '%s' exists,  IP: %pI4, has %u backends.", 
                svc->service_name, &svc->vip4, svc->count);
        
        struct sock_key pod_key;
        struct backend_pod *pod;
        // pod_key = lookup_random_pod(svc);
        pod_key=svc->backend_key[0];
        pod = map_lookup_elem(&Backend_Map, &pod_key);
        if (pod){
            printk("Backend_pod's IP: %pI4, Port: %u, belongs to Service: %s.\n", 
                    &pod->ip4, bpf_htons(pod->port), &svc->service_name);
            ctx->user_ip4 = pod->ip4;
            ctx->user_port = pod->port;
            return 0;
        }
    }
    return 0;
}


SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
    if(map_is_init==0){
        map_init();
    }
    // printk("no need to initialize map");
    // if (ctx->family == 2 && ctx->protocol== 6)//AF_INET && TCP
    if (ctx->family == 2)//AF_INET
    {
        int flag = __sock4_xlate_fwd(ctx);
    }
    return SK_PASS;
}