#include <uapi/linux/if_ether.h> //struct ethhdr
#include <uapi/linux/ip.h>  //struct iphdr
#include <uapi/linux/tcp.h> //struct tcphdr
#include <uapi/linux/udp.h> //struct tcphdr
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

//#define DEBUG

struct __attribute__((__packed__)) proxyhdr {
    __be32 orig_saddr;
    __be32 orig_daddr;
};

struct __attribute__((__packed__)) proxiedhdr {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    struct proxyhdr proxy;
    struct tcphdr tcp;
};

struct __attribute__((__packed__)) hdr {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
};

struct __attribute__((__packed__)) flow {
    __be32 srcaddr;
    __be16 srcport;
    __be16 dstport;
};

struct __attribute__((__packed__)) dst_server {
    unsigned char h_dest[ETH_ALEN];
    __be32 addr;
};

BPF_DEVMAP(loopback, 1);

#define IP_CSUM_OFF offsetof(struct proxiedhdr, ip) + offsetof(struct iphdr, check)

#define CTX_TYPE struct xdp_md
#define GROW_HEAD(ctx, len, _) \
    bpf_xdp_adjust_head(ctx, 0 - (int)len)
#define SHRINK_HEAD(ctx, len) \
    bpf_xdp_adjust_head(ctx, (int)len)

#define PASS XDP_PASS
#define REFLECT XDP_TX

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

static inline __u16 incr_add_check_l(__u16 old_check, __u32 new) {
    old_check = ~ntohs(old_check);
    __u32 l = (__u32)old_check + (new>>16) + (new&0xffff);
    return htons(~( (__u16)(l>>16) + (l&0xffff) ));
}

#define SIZE_DIFF (sizeof(struct proxiedhdr) - sizeof(struct hdr))

BPF_HASH(blocked_flows, struct flow, int);
BPF_HASH(redirect_flows, struct flow, int);

BPF_ARRAY(dst_servers, struct dst_server);
BPF_ARRAY(n_dst_servers, unsigned int, 1);

static int add_proxied_hdr(CTX_TYPE *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct hdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        return 0;
    }

    struct flow inflow = {
        .srcaddr = hdr->ip.saddr,
        .srcport = hdr->tcp.source,
        .dstport = hdr->tcp.dest
    };

    int *active_flow_p = redirect_flows.lookup(&inflow);
    int is_blocked = 0;
    int active_flow = 0;

    if (!active_flow_p) {
#ifdef DEBUG
        bpf_trace_printk("REDIRECTION: NON-ACTIVE FLOW %d:%d->%d\n",
                        (int)htonl(inflow.srcaddr),
                        htons(inflow.srcport),
                        htons(inflow.dstport));
#endif
        int *blocked_flow = blocked_flows.lookup(&inflow);
        if (!blocked_flow) {
            return 0;
        }
        if (*blocked_flow == -1) {
            return 0;
        }
#ifdef DEBUG
        bpf_trace_printk("REDIRECTION: Got blocked flow %u", ntohs(hdr->ip.id));
#endif
        is_blocked = 1;
        active_flow = *blocked_flow;
    } else {
        active_flow = *active_flow_p;
    }
#ifdef DEBUG
    bpf_trace_printk("REDIRECTION: ACTIVE FLOW\n");
#endif
    int flow = active_flow;
    struct dst_server *dst_server = dst_servers.lookup(&flow);
    if (!dst_server) {
#ifdef DEBUG
        bpf_trace_printk("REDIRECTION: BAD 1\n");
#endif
        return 0;
    }

    struct hdr orig = *hdr;
    if (GROW_HEAD(ctx, (SIZE_DIFF), data_size)) {
#ifdef DEBUG
        bpf_trace_printk("REDIRECTION: BAD 2\n");
#endif
        return 0;
    }

    data = (void*)(long)ctx->data;
    data_end = (void*)(long)ctx->data_end;
    struct proxiedhdr *newhdr = data;
    if (data + sizeof(*newhdr) > data_end) {
#ifdef DEBUG
        bpf_trace_printk("REDIRECTION: BAD 8\n");
#endif
        return 0;
    }

    __be16 newlen = htons(ntohs(orig.ip.tot_len) + SIZE_DIFF);


    newhdr->eth = orig.eth;
    memcpy(newhdr->eth.h_dest, dst_server->h_dest, ETH_ALEN);
    memcpy(newhdr->eth.h_source, orig.eth.h_dest, ETH_ALEN);
    newhdr->ip = orig.ip;
    newhdr->ip.protocol = 0x11;
    newhdr->ip.saddr = orig.ip.daddr;
    newhdr->ip.daddr = dst_server->addr;
    newhdr->ip.tot_len = newlen;
    //newhdr->proxy.orig_protocol = orig.ip.protocol;
    newhdr->proxy.orig_saddr = orig.ip.saddr;
    newhdr->proxy.orig_daddr = orig.ip.daddr;
    newhdr->tcp = orig.tcp;
    newhdr->udp.source = 0;
    if (is_blocked) {
        newhdr->udp.dest = 2;
    } else {
        newhdr->udp.dest = 1;
    }
    newhdr->udp.len = htons(ntohs(newlen) - sizeof(struct iphdr));
    newhdr->udp.check = 0;

    __be16 origproto;
    memcpy(&origproto, &orig.ip.ttl, 2);
    __be16 newproto;
    memcpy(&newproto, &newhdr->ip.ttl, 2);

    //newhdr->ip.check = incr_check_s(newhdr->ip.check,
    //        orig_proto, PROXY_PROTO);

    newhdr->ip.check = incr_check_l(newhdr->ip.check,
            ntohl(orig.ip.saddr), ntohl(newhdr->ip.saddr));
    newhdr->ip.check = incr_check_l(newhdr->ip.check,
            ntohl(orig.ip.daddr), ntohl(newhdr->ip.daddr));
    newhdr->ip.check = incr_check_s(newhdr->ip.check,
            ntohs(orig.ip.tot_len), ntohs(newhdr->ip.tot_len));
    newhdr->ip.check = incr_check_s(newhdr->ip.check,
            ntohs(origproto), ntohs(newproto));
    //s64 csumdiff = bpf_csum_diff(orig.ip.daddr, 4, newhdr->ip.daddr, 4, newhdr->tcp.check);
/*
    newhdr->tcp.check = incr_check_l(newhdr->tcp.check,
            ntohl(orig.ip.daddr), ntohl(newhdr->ip.daddr));
    newhdr->tcp.check = incr_check_s(newhdr->tcp.check,
            orig_tcplen, new_tcplen);
    newhdr->tcp.check = incr_add_check_l(newhdr->tcp.check, ntohl(newhdr->proxy.orig_daddr));
*/
#ifdef DEBUG
    bpf_trace_printk("REDIRECTING PACKET\n");
#endif
    return is_blocked == 0 ? 1 : 0;
}

static int rm_proxied_hdr(CTX_TYPE *ctx) {

    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct hdr *normhdr = data;
    if (data + sizeof(*normhdr) > data_end) {

#ifdef DEBUG
        bpf_trace_printk("IFACE TOO SMALL\n");
#endif
        return PASS;
    }
#ifdef DEBUG
    bpf_trace_printk("Iface got packet with id %u\n", ntohs(normhdr->ip.id));
#endif

    struct proxiedhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
#ifdef DEBUG
        bpf_trace_printk("IFACE TOO SMULL\n");
#endif
        return PASS;
    }


#ifdef DEBUG
    bpf_trace_printk("IFACE PROTOCOL IS 0x%x\n", hdr->ip.protocol);
#endif
    if (hdr->ip.protocol != 0x11) {
        return PASS;
    }

    if (hdr->udp.source == 0 && hdr->udp.dest == 0) {
#ifdef DEBUG
        bpf_trace_printk("IFACE GOT 0 SOURCE AND DEST\n");
#endif
        return bpf_redirect(1, 0);
    }
    if (hdr->udp.source == 0 && hdr->udp.dest != 1) {
#ifdef DEBUG
        bpf_trace_printk("IFACE GOT 0 SOURCE BUT BAD DEST \n");
#endif
        return PASS;
    }
#ifdef DEBUG
    bpf_trace_printk("IFACE GOT 0 SOURCE AND 1 DEST!!!\n");
#endif
    struct proxiedhdr orig = *hdr;

    if (SHRINK_HEAD(ctx, SIZE_DIFF)) {
#ifdef DEBUG
        bpf_trace_printk("CLIENT_IN: BAD 1\n");
#endif
        return PASS;
    }
    data = (void*)(long)ctx->data;
    data_end= (void*)(long)ctx->data_end;
    struct hdr *out = data;
    if (data + sizeof(*out) > data_end) {
#ifdef DEBUG
        bpf_trace_printk("CLIENT_IN: BAD 2\n");
#endif
        return PASS;
    }

    __be16 newlen = htons(ntohs(orig.ip.tot_len) - SIZE_DIFF);
#ifdef DEBUG
    bpf_trace_printk("IFACE shrinking packet to size %d\n", (int)ntohs(newlen));
#endif

    out->eth = orig.eth;
    out->ip = orig.ip;
    out->tcp = orig.tcp;

    out->ip.protocol = 0x06;
    out->ip.tot_len = newlen;
    out->ip.saddr = orig.proxy.orig_saddr;

    __be16 origproto;
    memcpy(&origproto, &orig.ip.ttl, 2);
    __be16 newproto;
    memcpy(&newproto, &out->ip.ttl, 2);

    out->ip.check = incr_check_l(out->ip.check,
            ntohl(orig.ip.saddr), ntohl(out->ip.saddr));
    out->ip.check = incr_check_s(out->ip.check,
            ntohs(orig.ip.tot_len), ntohs(out->ip.tot_len));
    out->ip.check = incr_check_s(out->ip.check,
            ntohs(origproto), ntohs(newproto));

    out->tcp.check = incr_check_l(out->tcp.check,
            ntohl(orig.proxy.orig_saddr), ntohl(out->ip.saddr));
    out->tcp.check = incr_check_l(out->tcp.check,
            ntohl(orig.proxy.orig_daddr), ntohl(out->ip.daddr));

    return PASS;
}


int monitor_iface_ingress(CTX_TYPE *ctx) {
    rm_proxied_hdr(ctx);
    int rtn = add_proxied_hdr(ctx);
    if (rtn) {
        return REFLECT;
    }
    return PASS;
}

BPF_ARRAY(ifindex, int, 1);

#undef PASS
#define PASS TC_ACT_OK
int check_redirect(struct __sk_buff *ctx) {
    bpf_skb_pull_data(ctx, sizeof(struct hdr));
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
#ifdef DEBUG
    bpf_trace_printk("skb size: %d\n", data_end - data);
#endif

    struct hdr *normhdr = data;
    if (data + sizeof(*normhdr) > data_end) {
#ifdef DEBUG
        bpf_trace_printk("IFACE REDIR TOO SMALL\n");
#endif
        return PASS;
    }
#ifdef DEBUG
    bpf_trace_printk("dstport is %d\n", ntohs(normhdr->tcp.dest));
#endif

    if (normhdr->ip.protocol == 0x06) {
        struct flow inflow = {
            .srcaddr = normhdr->ip.saddr,
            .srcport = normhdr->tcp.source,
            .dstport = normhdr->tcp.dest
        };

        int *blocked = blocked_flows.lookup(&inflow);

        if (blocked) {
#ifdef DEBUG
            bpf_trace_printk("IFACE REDIR GOT BLOCKED TCP PKT\n");
#endif
            return bpf_redirect(1, 0);
        } else if (blocked){
#ifdef DEBUG
            bpf_trace_printk("Un-blocked flow %d->%d\n", ntohs(inflow.srcport), ntohs(inflow.dstport));
#endif
        } else {
#ifdef DEBUG
            bpf_trace_printk("Non-blocked flow %d->%d\n", ntohs(inflow.srcport), ntohs(inflow.dstport));
#endif
        }
    } else if (normhdr->ip.protocol == 0x11) {
        struct proxiedhdr *hdr = data;
        if (data + sizeof(*hdr) > data_end) {
            return PASS;
        }
        struct flow inflow = {
            .srcaddr = hdr->proxy.orig_saddr,
            .srcport = hdr->tcp.source,
            .dstport = hdr->tcp.dest
        };

        int *blocked = blocked_flows.lookup(&inflow);

        if (blocked) {
            bpf_trace_printk("IFACE REDIR got BLOCKED PROXIED PKT\n");
            return bpf_redirect(1,0);
        }
    }
#ifdef DEBUG
    bpf_trace_printk("Protocol is: 0x%x, ID: %u\n", normhdr->ip.protocol, ntohs(normhdr->ip.id));
#endif
    return PASS;
}



BPF_HASH(ack_flows, struct flow, uint32_t);

int monitor_iface_egress(struct __sk_buff *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct hdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
#ifdef DEBUG
        bpf_trace_printk("Iface egress too small");
#endif
        return PASS;
    }

    if (hdr->ip.protocol != 0x06) {
        return PASS;
    }

    struct flow outflow = {
        .srcaddr = hdr->ip.daddr,
        .srcport = hdr->tcp.dest,
        .dstport = hdr->tcp.source
    };

    int *ack = ack_flows.lookup(&outflow);

    if (!ack) {
#ifdef DEBUG
        bpf_trace_printk("NO ACK FLOW\n");
#endif
        return PASS;
    }

    struct hdr orig = *hdr;

    memcpy(hdr->eth.h_source, orig.eth.h_dest, sizeof(orig.eth.h_dest));
    memcpy(hdr->eth.h_dest, orig.eth.h_source, sizeof(orig.eth.h_dest));

    hdr->ip.daddr = orig.ip.saddr;
    hdr->ip.saddr = orig.ip.daddr;

    hdr->tcp.source = orig.tcp.dest;
    hdr->tcp.dest = orig.tcp.source;

    hdr->tcp.ack_seq = *ack;
    hdr->tcp.seq = orig.tcp.ack_seq;

    hdr->tcp.check = incr_check_l(hdr->tcp.check,
            ntohl(orig.tcp.ack_seq), ntohl(hdr->tcp.ack_seq));

    hdr->tcp.check = incr_check_l(hdr->tcp.check,
            ntohl(orig.tcp.seq), ntohl(hdr->tcp.seq));

    ack_flows.delete(&outflow);

#ifdef DEBUG
    bpf_trace_printk("Iface egree: RESPONDING WITH ACK!\n");
#endif
    int zero = 0;
    int *IFINDEX = ifindex.lookup(&zero);
    if (!IFINDEX) {
#ifdef DEBUG
        bpf_trace_printk("NO IFINDEX\n");
#endif
        return PASS;
    }
    return bpf_redirect(*IFINDEX, BPF_F_INGRESS);
}

int monitor_lo_ingress(struct __sk_buff *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct hdr *normhdr = data;
    if (data + sizeof(*normhdr) > data_end) {
#ifdef DEBUG
        bpf_trace_printk("LO TOO SMALL\n");
#endif
        return PASS;
    }

    if (normhdr->ip.protocol == 0x06) {
        struct flow inflow = {
            .srcaddr = normhdr->ip.saddr,
            .srcport = normhdr->tcp.source,
            .dstport = normhdr->tcp.dest
        };

        int *blocked = blocked_flows.lookup(&inflow);

        if (blocked) {
#ifdef DEBUG
            bpf_trace_printk("LO GOT BLOCKED TCP PKT %u\n", ntohs(normhdr->ip.id));
#endif
            return bpf_redirect(1, 0);
        }
        int zero = 0;
        int *IFINDEX = ifindex.lookup(&zero);
        if (!IFINDEX) {
#ifdef DEBUG
            bpf_trace_printk("NO IFINDEX\n");
#endif
            return PASS;
         }
#ifdef DEBUG
        bpf_trace_printk("LO Nonblocked flow %u: %d->%d", 
                        ntohs(normhdr->ip.id),
                        (int)ntohs(inflow.srcport),
                         (int)ntohs(inflow.dstport));
#endif
        return bpf_redirect(*IFINDEX, BPF_F_INGRESS);
    }

    struct proxiedhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
#ifdef DEBUG
        bpf_trace_printk("LO TOO SMULL\n");
#endif
        return PASS;
    }

#ifdef DEBUG
    bpf_trace_printk("LO PROTOCOL IS 0x%x\n", hdr->ip.protocol);
#endif
    if (hdr->ip.protocol != 0x11) {
        return PASS;
    }

    if (hdr->udp.source != 0 || hdr->udp.dest != 2) {
#ifdef DEBUG
        bpf_trace_printk("LO GOT NON-0 SOURCE AND DEST (%d and %d)\n",
                         htons(hdr->udp.source), htons(hdr->udp.dest));
#endif
        return PASS;
    }

    struct flow inflow = {
        .srcaddr = hdr->proxy.orig_saddr,
        .srcport = hdr->tcp.source,
        .dstport = hdr->tcp.dest
    };

    int *in = blocked_flows.lookup(&inflow);
    if (in) {
#ifdef DEBUG
        bpf_trace_printk("LO RETURN TO LO\n");
#endif
        return bpf_redirect(1, 0);
    }
    hdr->udp.dest = 1;
#ifdef DEBUG
    bpf_trace_printk("LO RETURN %u TO IFACE\n", ntohs(hdr->ip.id));
#endif
    int zero = 0;
    int *IFINDEX = ifindex.lookup(&zero);
    if (!IFINDEX) {
#ifdef DEBUG
        bpf_trace_printk("NO IFINDEX\n");
#endif
        return PASS;
    }
    hdr->udp.dest = 1;

    return bpf_redirect(*IFINDEX, 0);
}


