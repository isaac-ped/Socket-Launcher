#include <uapi/linux/if_ether.h> //struct ethhdr
#include <uapi/linux/ip.h>  //struct iphdr
#include <uapi/linux/tcp.h> //struct tcphdr
#include <uapi/linux/udp.h> //struct tcphdr
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

BPF_DEVMAP(devmap, 10);
BPF_HASH(ip_map, __be32, unsigned int);

struct __attribute__((__packed__)) inhdr {
    struct ethhdr eth;
    struct iphdr ip;
};

#define PASS XDP_PASS

int monitor_ingress(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct inhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("CLIENT_IN: too small\n");
        return PASS;
    }

    __be32 daddr = hdr->ip.daddr;
    int *dev_p = ip_map.lookup(&daddr);

    if (!dev_p) {
        return PASS;
    }
    int dev = *dev_p;

    return devmap.redirect_map(dev, 0);
}
