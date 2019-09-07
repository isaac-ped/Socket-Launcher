#include <uapi/linux/if_ether.h> //struct ethhdr
#include <uapi/linux/ip.h>  //struct iphdr
#include <uapi/linux/tcp.h> //struct tcphdr
#include <uapi/linux/udp.h> //struct tcphdr
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

struct __attribute__((__packed__)) inhdr {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
};

struct __attribute__((__packed__)) flow {
    __be32 srcaddr;
    __be16 srcport;
    __be16 dstport;
};

BPF_HASH(blocked_flows, struct flow, int);


#define CTX_TYPE struct xdp_md
#define PASS XDP_PASS
#define REFLECT XDP_TX
#define DROP XDP_DROP

int monitor_ingress(CTX_TYPE *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct inhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("DROP_CLIENT: too small\n");
        return PASS;
    }
    if (hdr->eth.h_proto != htons(0x0800)) {
        bpf_trace_printk("DROP_CLIENT: Not IP\n");
        return PASS;
    }

    struct flow flow = {
        .srcaddr = hdr->ip.saddr,
        .srcport = hdr->tcp.source,
        .dstport = hdr->tcp.dest
    };

    int *block = blocked_flows.lookup(&flow);

    if (block && *block) {
        bpf_trace_printk("DROP_CLIENT: Dropping\n");
        return DROP;
    }
    bpf_trace_printk("DROP_CLIENT: Not Dropping\n");
    return PASS;
}
