#include <uapi/linux/if_ether.h> //struct ethhdr
#include <uapi/linux/ip.h>  //struct iphdr
#include <uapi/linux/tcp.h> //struct tcphdr
#include <uapi/linux/udp.h> //struct tcphdr
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>


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
#define GROW_HEAD(ctx, len) \
    bpf_xdp_adjust_head(ctx, 0- (len))
#define SHRINK_HEAD(ctx, len) \
    bpf_xdp_adjust_head(ctx, (len))

#define REFLECT XDP_TX

#define DEBUG

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

int try_redirect(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct hdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        return XDP_PASS;
    }

    struct flow inflow = {
        .srcaddr = hdr->ip.saddr,
        .srcport = hdr->tcp.source,
        .dstport = hdr->tcp.dest
    };

    int *active_flow = redirect_flows.lookup(&inflow);

    if (!active_flow) {
#ifdef DEBUG
        bpf_trace_printk("REDIRECTION: NON-ACTIVE FLOW %d:%d->%d\n",
                        (int)htonl(inflow.srcaddr),
                        htons(inflow.srcport),
                        htons(inflow.dstport));
#endif
        return XDP_PASS;
    }
#ifdef DEBUG
    bpf_trace_printk("REDIRECTION: ACTIVE FLOW\n");
#endif
    int flow = *active_flow;
    struct dst_server *dst_server = dst_servers.lookup(&flow);
    if (!dst_server) {
#ifdef DEBUG
        bpf_trace_printk("REDIRECTION: BAD 1\n");
#endif
        return XDP_PASS;
    }

    bpf_trace_printk("grow before: %d\n", data_end - data);
    struct hdr orig = *hdr;
    if (bpf_xdp_adjust_head(ctx, 0 - (int)SIZE_DIFF)) {
#ifdef DEBUG
        bpf_trace_printk("REDIRECTION: BAD 2\n");
#endif
        return XDP_PASS;
    }
    return XDP_PASS;

    data = (void*)((unsigned long)ctx->data);
    data_end = (void*)(long)ctx->data_end;
    struct proxiedhdr *newhdr = data;
    if (data + sizeof(*newhdr) > data_end) {
#ifdef DEBUG
        bpf_trace_printk("REDIRECTION: BAD 8\n");
#endif
        return XDP_PASS;
    }
    bpf_trace_printk("grow after: %d\n", data_end - data);

    __be16 newlen = htons(ntohs(orig.ip.tot_len) + SIZE_DIFF);

    bpf_trace_printk("Growing packet to size %d\n", (int)ntohs(newlen));

    //newhdr->eth = orig.eth;
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
    newhdr->udp.dest = 1;
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
    bpf_trace_printk("REFLECTING PACKET\n");
#endif
    return XDP_PASS;
    return XDP_TX;
}


static inline int try_loopback(CTX_TYPE *ctx) {
    return 1;

    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct hdr *normhdr = data;
    if (data + sizeof(*normhdr) > data_end) {
#ifdef DEBUG
        bpf_trace_printk("IFACE TOO SMALL\n");
#endif
        return XDP_PASS;
    }
    bpf_trace_printk("IP ID: %u\n", ntohs(normhdr->ip.id));
    /*
    if (normhdr->ip.protocol == 0x06) {
        struct flow inflow = {
            .srcaddr = normhdr->ip.saddr,
            .srcport = normhdr->tcp.source,
            .dstport = normhdr->tcp.dest
        };

        int *blocked = blocked_flows.lookup(&inflow);

        if (blocked && *blocked) {
#ifdef DEBUG
            bpf_trace_printk("IFACE GOT BLOCKED TCP PKT\n");
#endif
            int x = loopback.redirect_map(0, 0);//BPF_F_INGRESS);
            if (x == XDP_REDIRECT) {
                bpf_trace_printk("Successful!\n");
            } else {
                bpf_trace_printk("Failed: %d\n", x);
            }
            return x;
            //int rtn = loopback.redirect_map(0,0);
            //if (rtn == XDP_ABORTED) {
            //    bpf_trace_printk("WARNING: IFACE COULD NOT REDIRECT\n");
            //}
            //return rtn;
        }
    }
    */

    struct proxiedhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
#ifdef DEBUG
        bpf_trace_printk("IFACE TOO SMULL\n");
#endif
        return XDP_PASS;
    }


#ifdef DEBUG
    bpf_trace_printk("IFACE PROTOCOL IS 0x%x\n", hdr->ip.protocol);
#endif
    if (hdr->ip.protocol != 0x11) {
        return XDP_PASS;
    }

    if (hdr->udp.source == 0 && hdr->udp.dest == 0) {
#ifdef DEBUG
        bpf_trace_printk("IFACE GOT 0 SOURCE AND DEST\n");
#endif
        return loopback.redirect_map(0, 0);
    }
    if (hdr->udp.source == 0 && hdr->udp.dest != 1) {
#ifdef DEBUG
        bpf_trace_printk("IFACE GOT 0 SOURCE BUT BAD DEST \n");
#endif
        return XDP_PASS;
    }
#ifdef DEBUG
    bpf_trace_printk("IFACE GOT 0 SOURCE AND 1 DEST!!!\n");
#endif
    struct proxiedhdr orig = *hdr;

    bpf_trace_printk("Size before: %d\n", data_end - data);

    if (SHRINK_HEAD(ctx, SIZE_DIFF)) {
#ifdef DEBUG
        bpf_trace_printk("CLIENT_IN: BAD 1\n");
#endif
      return XDP_PASS;
    }
    void *data2 = (void*)((unsigned long)ctx->data);
    void *data_end2= (void*)(long)ctx->data_end;
    struct hdr *out = data2;
    if (data2 + sizeof(*out) > data_end2) {
#ifdef DEBUG
        bpf_trace_printk("CLIENT_IN: BAD 2\n");
#endif
        return XDP_PASS;
    }

    bpf_trace_printk("Size after: %d\n", data_end2 - data2);
    bpf_trace_printk("IP ID BEFORE SET: %u\n", ntohs(out->ip.id));

    __be16 newlen = htons(ntohs(orig.ip.tot_len) - SIZE_DIFF);
#ifdef DEBUG
    bpf_trace_printk("IFACE shrinking packet to size %d\n", (int)ntohs(newlen));
#endif

    memcpy(&out->eth, &orig.eth, sizeof(orig.eth));
    memcpy(&out->ip, &orig.ip, sizeof(orig.ip));
    //out->eth = orig.eth;
    //out->ip = orig.ip;
    memcpy(&out->tcp, &orig.tcp, sizeof(orig.tcp));

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
            ntohl(orig.proxy.orig_daddr), ntohl(out->ip.daddr));
    out->tcp.check = incr_check_l(out->tcp.check,
            ntohl(orig.proxy.orig_saddr), ntohl(out->ip.saddr));
    bpf_trace_printk("IP ID AFTER SET: %u(%u)\n", ntohs(out->ip.id), ntohs(orig.ip.id));
    return 1;
}


int monitor_iface_ingress(CTX_TYPE *ctx) {
    int rtn = try_loopback(ctx);
    if (rtn == 1) {
        bpf_trace_printk("resize succeeded\n");
        return XDP_PASS;
    }
    if (rtn == XDP_PASS) {
        //return try_redirect(ctx);
    }
    bpf_trace_printk("NON-PASS RETURN\n");
    return rtn;
}

#define IFINDEX 2

#undef PASS
#define PASS TC_ACT_OK
int check_redirect(struct __sk_buff *ctx) {
    bpf_skb_pull_data(ctx, sizeof(struct hdr));
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    bpf_trace_printk("skb size: %d\n", data_end - data);

    struct hdr *normhdr = data + SIZE_DIFF;
    if (data + sizeof(*normhdr) > data_end) {
        bpf_trace_printk("IFACE REDIR TOO SMALL\n");
        return PASS;
    }
    bpf_trace_printk("dstport is %d\n", ntohs(normhdr->tcp.dest));

    if (normhdr->ip.protocol == 0x06) {
        struct flow inflow = {
            .srcaddr = normhdr->ip.saddr,
            .srcport = normhdr->tcp.source,
            .dstport = normhdr->tcp.dest
        };

        int *blocked = blocked_flows.lookup(&inflow);

        if (blocked && *blocked) {
            bpf_trace_printk("IFACE REDIR GOT BLOCKED TCP PKT\n");
            return bpf_redirect(1, 0);
            //int rtn = loopback.redirect_map(0,0);
            //if (rtn == XDP_ABORTED) {
            //    bpf_trace_printk("WARNING: IFACE COULD NOT REDIRECT\n");
            //}
            //return rtn;
        } else if (blocked){
            bpf_trace_printk("Un-blocked flow %d->%d\n", ntohs(inflow.srcport), ntohs(inflow.dstport));
        } else {
            bpf_trace_printk("Non-blocked flow %d->%d\n", ntohs(inflow.srcport), ntohs(inflow.dstport));
        }
    }
    bpf_trace_printk("Protocol is: 0x%x, ID: %u\n", normhdr->ip.protocol, ntohs(normhdr->ip.id));
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
    return bpf_redirect(IFINDEX, BPF_F_INGRESS);
}

int monitor_lo_ingress(struct __sk_buff *ctx) {
    bpf_trace_printk("LO GOT PKT\n");
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

        if (blocked && *blocked) {
//#ifdef DEBUG
            bpf_trace_printk("LO GOT BLOCKED TCP PKT %d->%d\n", ntohs(inflow.srcport), ntohs(inflow.dstport));
//#endif
            return bpf_redirect(1, 0);//BPF_F_INGRESS);
        }
        return PASS;
#ifdef DEBUG
        bpf_trace_printk("LO Nonblocked flow: %d->%d\n", (int)ntohs(inflow.srcport),
                         (int)ntohs(inflow.dstport));
#endif
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

    if (hdr->udp.source != 0 || hdr->udp.dest != 0) {
#ifdef DEBUG
        bpf_trace_printk("LO GOT NON-0 SOURCE AND DEST\n");
#endif
        return PASS;
    }

    struct flow inflow = {
        .srcaddr = hdr->proxy.orig_saddr,
        .srcport = hdr->tcp.source,
        .dstport = hdr->tcp.dest
    };

    int *in = blocked_flows.lookup(&inflow);
    if (in && *in) {
//#ifdef DEBUG
        bpf_trace_printk("LO RETURN TO LO\n");
//#endif
        return bpf_redirect(1, 0);
    }
    hdr->udp.dest = 1;
//#ifdef DEBUG
    bpf_trace_printk("LO RETURN TO IFACE\n");
//#endif
    return bpf_redirect(IFINDEX, BPF_F_INGRESS);
}


