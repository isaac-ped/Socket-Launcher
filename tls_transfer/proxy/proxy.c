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

struct __attribute__((__packed__)) outflow {
    __be16 srcport;
    __be16 dstport;
};

struct __attribute__((__packed__)) flow {
    __be32 srcaddr;
    __be16 srcport;
    __be16 dstport;
};

#define IP_CSUM_OFF offsetof(struct inhdr, ip) + offsetof(struct iphdr, check)

BPF_ARRAY(dst_servers, struct dst_addr);
BPF_ARRAY(n_dst_servers, unsigned int);
BPF_HASH(active_ports, __be16, int);
BPF_TABLE("lru_hash", struct flow, int, inflows, 65536);
BPF_TABLE("lru_hash", struct outflow, struct dst_addr, outflows, 65536);
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
__u16 rtn = htons(~( (__u16)(l>>16) + (l&0xffff) ));
if (rtn == 0xffff) {
    return 0xfeff;
}
return rtn;
}

/* Incrementaly update a checksum, given old and new 32bit words */
static inline __u16 incr_check_l(__u16 old_check, __u32 old, __u32 new)
{ /* see RFC's 1624, 1141 and 1071 for incremental checksum updates */
__u32 l;
old_check = ~ntohs(old_check);
old = ~old;
l = (__u32)old_check + (old>>16) + (old&0xffff)
+ (new>>16) + (new&0xffff);
__u16 rtn = htons(~( (__u16)(l>>16) + (l&0xffff) ));
if (rtn == 0xffff) {
    return 0xfeff;
}
return rtn;
}

static int handle_outflow(struct inhdr *hdr) {
    __be16 port = hdr->tcp.source;
    int *has_port = active_ports.lookup(&port);
    if (!has_port) {
        return PASS;
    }

    struct outflow curr_flow = {
        .srcport = hdr->tcp.source,
        .dstport = hdr->tcp.dest,
    };

    struct dst_addr *client_p = outflows.lookup(&curr_flow);

    if (!client_p) {
        //bpf_trace_printk("PROXY: nonmatch outflow %d->%d\n",
                         //htons(curr_flow.srcport), htons(curr_flow.dstport));
        return PASS;
    }
    struct dst_addr client = *client_p;
    if (hdr->tcp.fin) {
        //bpf_trace_printk("PROXY: Deleting outflow\n");
        outflows.delete(&curr_flow);

        struct flow curr_inflow = {
            .srcaddr = client.addr,
            .srcport = hdr->tcp.dest,
            .dstport = hdr->tcp.source
        };
        int *idx = inflows.lookup(&curr_inflow);
        int flowi = -1;
        if (idx && *idx > 0) {
            flowi = -*idx;
        }
        //inflows.update(&curr_inflow, &flowi);
    }

    //bpf_trace_printk("PROXY: Matched outflow %d:%d->%d\n",
                     //(int)htonl(hdr->ip.saddr), htons(curr_flow.srcport), htons(curr_flow.dstport));

    struct inhdr orig = *hdr;
    memcpy(hdr->eth.h_source, orig.eth.h_dest, sizeof(orig.eth.h_dest));
    hdr->ip.saddr = orig.ip.daddr;
    hdr->ip.daddr = client.addr;
    memcpy(hdr->eth.h_dest, client.h_dest, ETH_ALEN);

    hdr->ip.check = incr_check_l(hdr->ip.check,
            ntohl(orig.ip.saddr), ntohl(client.addr));
    hdr->tcp.check = incr_check_l(hdr->tcp.check,
            ntohl(orig.ip.saddr), ntohl(client.addr));

    return REFLECT;
}


static int handle_inflow(struct inhdr *hdr) {
    __be16 port = hdr->tcp.dest;
    struct flow curr_flow = {
        .srcaddr = hdr->ip.saddr,
        .srcport = hdr->tcp.source,
        .dstport = hdr->tcp.dest
    };

    int *active_flow_p = inflows.lookup(&curr_flow);
    int active_flow = 0;

    if (!active_flow_p) {
        int *has_port = active_ports.lookup(&port);

        if (!has_port) {
            //bpf_trace_printk("PROXY: Unknown inport %d:%d->%d\n",
                            //curr_flow.srcaddr, htons(curr_flow.srcport), htons(curr_flow.dstport));
            return PASS;
        }

        if (!*has_port) {
            //bpf_trace_printk("PROXY: Inactive inport\n");
            return PASS;
        }

        //bpf_trace_printk("PROXY: new inflow\n");
        int zero = 0;
        unsigned int *new_flow = last_flow.lookup(&zero);
        if (!new_flow) {
            //bpf_trace_printk("no last flow?\n");
            return PASS;
        }
        unsigned int *max_flow = n_dst_servers.lookup(&zero);
        if (!max_flow) {
            //bpf_trace_printk("no dst server??\n");
            return PASS;
        }
        *new_flow = (*new_flow + 1) % (*max_flow);

        int flow = *new_flow + 1;

        if (hdr->tcp.rst || hdr->tcp.fin) {
            active_flow = flow;
            //bpf_trace_printk("PROXY: Deleting new inflow\n");
        } else {
            inflows.insert(&curr_flow, &flow);
            active_flow = flow;
        }
    } else {
        active_flow = *active_flow_p;
    }
    if (active_flow == 0) {
        //bpf_trace_printk("PROXY: inBAD 5\n");
        return PASS;
    }
    if (hdr->tcp.fin || active_flow < 0) {
        //bpf_trace_printk("PROXY: Deleting old inflow to %d\n", active_flow);
        inflows.delete(&curr_flow);
    }

    unsigned int flow = active_flow - 1;
    struct dst_addr *dst_server = dst_servers.lookup(&flow);
    if (!dst_server) {
        //bpf_trace_printk("PROXY: inBAD 1\n");
        return PASS;
    }

    struct outflow rtn_flow = {
        .dstport = hdr->tcp.source,
        .srcport = hdr->tcp.dest
    };

    struct dst_addr client = {
        .addr = hdr->ip.saddr,
        .port = hdr->tcp.source,
    };
    memcpy(client.h_dest, hdr->eth.h_source, ETH_ALEN);
    if ((!hdr->tcp.rst) && (!hdr->tcp.fin) && active_flow > 0) {
        //bpf_trace_printk("PROXY: update rtn flow %d:%d->%d\n",
        //                  (int)ntohl(hdr->ip.daddr), htons(rtn_flow.srcport), htons(rtn_flow.dstport));
        outflows.update(&rtn_flow, &client);
    }

    struct inhdr orig = *hdr;
    //memcpy(hdr->eth.h_dest, orig.eth.h_source, sizeof(orig.eth.h_source));
    memcpy(hdr->eth.h_source, orig.eth.h_dest, sizeof(orig.eth.h_dest));
    memcpy(hdr->eth.h_dest, dst_server->h_dest, sizeof(dst_server->h_dest));
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
        //bpf_trace_printk("REFLECTING OUT\n");
        return REFLECT;
    }
    //bpf_trace_printk("PASSING\n");
    return PASS;
}
