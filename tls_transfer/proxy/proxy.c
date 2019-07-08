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

struct __attribute__((__packed__)) proxyhdr {
    __be32 orig_saddr;
    __be32 orig_daddr;
};

struct __attribute__((__packed__)) outhdr {
    struct ethhdr eth;
    struct iphdr ip_new;
    struct udphdr udp;
    struct proxyhdr proxy;
    struct tcphdr tcp;
};

struct __attribute__((__packed__)) dst_addr {
    unsigned char h_dest[ETH_ALEN];
    __be32 addr;
    __be16 port;
};

struct __attribute__((__packed__)) flow {
    __be32 srcaddr;
    __be16 srcport;
    __be16 dstport;
};

#define IP_CSUM_OFF offsetof(struct inhdr, ip) + offsetof(struct iphdr, check)

BPF_ARRAY(dst_servers, struct dst_addr);
BPF_ARRAY(n_dst_servers, unsigned int, 1);
BPF_HASH(active_ports, __be16, int);
BPF_HASH(inflows, struct flow, int);
BPF_HASH(outflows, struct flow, struct dst_addr);
BPF_PERCPU_ARRAY(last_flow, int, 1);


//#define IS_TC_

#ifdef IS_TC_

#define CTX_TYPE struct __sk_buff
#define GROW_HEAD(ctx, adjust, size) \
    0//bpf_skb_change_head(ctx, 14, 0)

#define PASS TC_ACT_OK
#define REFLECT bpf_redirect(ctx->ifindex, 0)

#else

#define CTX_TYPE struct xdp_md
#define GROW_HEAD(ctx, len, _) \
    bpf_xdp_adjust_head(ctx, 0 - (int)len)

#define PASS XDP_PASS
#define REFLECT XDP_TX
#define DROP XDP_DROP

#endif

/* Incrementaly update a checksum, given old and new 16bit words */
static inline __u16 incr_check_s(__u16 old_check, __u16 old, __u16 new)
{ /* see RFC's 1624, 1141 and 1071 for incremental checksum updates */
__u32 l;
old_check = ~ntohs(old_check);
old = ~old;
l = (__u32)old_check + old + new;
return htons(~( (__u16)(l>>16) + (l&0xffff) ));
}

/* Incrementaly update a checksum, given old and new 32bit words */
static inline __u16 incr_check_l(__u16 old_check, __u32 old, __u32 new)
{ /* see RFC's 1624, 1141 and 1071 for incremental checksum updates */
__u32 l;
old_check = ~ntohs(old_check);
old = ~old;
l = (__u32)old_check + (old>>16) + (old&0xffff)
+ (new>>16) + (new&0xffff);
return htons(~( (__u16)(l>>16) + (l&0xffff) ));
}

static int handle_outflow(struct inhdr *hdr) {
    struct flow curr_flow = {
        .srcaddr = hdr->ip.saddr,
        .srcport = hdr->tcp.source,
        .dstport = hdr->tcp.dest,
    };

    struct dst_addr *client = outflows.lookup(&curr_flow);

    if (!client) {
        bpf_trace_printk("PROXY: nonmatch outflow %d:%d->%d\n",
                         curr_flow.srcaddr, htons(curr_flow.srcport), htons(curr_flow.dstport));
        return PASS;
    }


    bpf_trace_printk("PROXY: Matched outflow %d:%d->%d\n",
                     curr_flow.srcaddr, htons(curr_flow.srcport), htons(curr_flow.dstport));

    struct inhdr orig = *hdr;
    memcpy(hdr->eth.h_dest, orig.eth.h_source, sizeof(orig.eth.h_source));
    memcpy(hdr->eth.h_source, orig.eth.h_dest, sizeof(orig.eth.h_dest));
    hdr->ip.saddr = orig.ip.daddr;
    hdr->ip.daddr = client->addr;
    memcpy(hdr->eth.h_dest, client->h_dest, ETH_ALEN);

    hdr->ip.check = incr_check_l(hdr->ip.check,
            ntohl(orig.ip.saddr), ntohl(client->addr));
    hdr->tcp.check = incr_check_l(hdr->tcp.check,
            ntohl(orig.ip.saddr), ntohl(client->addr));

    return REFLECT;
}


static int handle_inflow(struct inhdr *hdr) {
    __be16 port = hdr->tcp.dest;
    struct flow curr_flow = {
        .srcaddr = hdr->ip.saddr,
        .srcport = hdr->tcp.source,
        .dstport = hdr->tcp.dest
    };

    int *active_flow = inflows.lookup(&curr_flow);

    if (active_flow && (*active_flow) < 0) {
        bpf_trace_printk("PROXY: Drop for now: %d:%d->%d\n",
                         curr_flow.srcaddr, htons(curr_flow.srcport), htons(curr_flow.dstport));
        return DROP;
    }

    if (!active_flow) {
        int *has_port = active_ports.lookup(&port);

        if (!has_port) {
            bpf_trace_printk("PROXY: Unknown inport %d:%d->%d\n",
                            curr_flow.srcaddr, htons(curr_flow.srcport), htons(curr_flow.dstport));
            return PASS;
        }

        if (!*has_port) {
            bpf_trace_printk("PROXY: Inactive inport\n");
            return PASS;
        }

        bpf_trace_printk("PROXY: new inflow\n");
        int zero = 0;
        unsigned int *new_flow = last_flow.lookup(&zero);
        if (!new_flow) {
            return PASS;
        }
        unsigned int *max_flow = n_dst_servers.lookup(&zero);
        if (!max_flow) {
            return PASS;
        }
        *new_flow = (*new_flow + 1) % (*max_flow);

        int flow = *new_flow + 1;

        active_flow = inflows.lookup_or_init(&curr_flow, &flow);

    }
    if (!active_flow) {
        bpf_trace_printk("PROXY: inBAD 5\n");
        return PASS;
    }

    unsigned int flow = *active_flow - 1;
    struct dst_addr *dst_server = dst_servers.lookup(&flow);
    if (!dst_server) {
        bpf_trace_printk("PROXY: inBAD 1\n");
        return PASS;
    }

    struct flow rtn_flow = {
        .dstport = hdr->tcp.source,
        .srcaddr = dst_server->addr,
        .srcport = hdr->tcp.dest
    };
    bpf_trace_printk("PROXY: update rtn flow %d:%d->%d\n",
                     rtn_flow.srcaddr, htons(rtn_flow.srcport), htons(rtn_flow.dstport));

    struct dst_addr client = {
        .addr = hdr->ip.saddr,
        .port = hdr->tcp.source,
    };
    memcpy(client.h_dest, hdr->eth.h_dest, ETH_ALEN);
    outflows.update(&rtn_flow, &client);

    struct inhdr orig = *hdr;
    memcpy(hdr->eth.h_dest, orig.eth.h_source, sizeof(orig.eth.h_source));
    memcpy(hdr->eth.h_source, orig.eth.h_dest, sizeof(orig.eth.h_dest));
    hdr->ip.saddr = orig.ip.daddr;
    hdr->ip.daddr = dst_server->addr;
    hdr->tcp.dest = dst_server->port;

    hdr->ip.check = incr_check_l(hdr->ip.check, ntohl(orig.ip.saddr), ntohl(dst_server->addr));
    hdr->tcp.check = incr_check_l(hdr->tcp.check, ntohl(orig.ip.saddr), ntohl(dst_server->addr));
    hdr->tcp.check = incr_check_s(hdr->tcp.check, ntohs(orig.tcp.dest), ntohs(hdr->tcp.dest));

    return REFLECT;
}

int monitor_ingress(CTX_TYPE *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct inhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        return PASS;
    }

    int rtn = handle_inflow(hdr);

    if (rtn != PASS) {
        return rtn;
    }

    if (handle_outflow(hdr) == REFLECT) {
        bpf_trace_printk("REFLECTING OUT\n");
        return REFLECT;
    }
    bpf_trace_printk("PASSING\n");
    return PASS;
}
