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

#define PROXY_PROTO 0xd

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

struct __attribute__((__packed__)) dst_server {
    __be32 addr;
};

struct __attribute__((__packed__)) flow {
    __be32 srcaddr;
    __be16 srcport;
    __be16 dstport;
};

#define IP_CSUM_OFF offsetof(struct inhdr, ip) + offsetof(struct iphdr, check)

BPF_ARRAY(dst_servers, struct dst_server);
BPF_ARRAY(n_dst_servers, unsigned int, 1);
BPF_HASH(active_ports, __be16, int);
BPF_HASH(active_flows, struct flow, unsigned int);
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

int monitor_ingress(CTX_TYPE *ctx) {
    /*skb_headroom(ctx);
    if (GROW_HEAD(ctx, sizeof(struct iphdr), 0)) {
        bpf_trace_printk("PROXY: BAD 2\n");
        return PASS;
    }*/

    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct inhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        return PASS;
    }

    __be16 port = hdr->tcp.dest;
    int *has_port = active_ports.lookup(&port);

    if (!has_port) {
        bpf_trace_printk("PROXY: Unknown port\n");
        return PASS;
    }

    if (!*has_port) {
        bpf_trace_printk("PROXY: Inactive port\n");
        return PASS;
    }

    struct flow curr_flow = {
        hdr->ip.saddr,
        hdr->tcp.source,
        hdr->tcp.dest
    };

    int *active_flow = active_flows.lookup(&curr_flow);

    if (!active_flow) {
        bpf_trace_printk("PROXY: new flow\n");
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

        int flow = *new_flow;
        active_flow = active_flows.lookup_or_init(&curr_flow, &flow);
    }
    if (!active_flow) {
        bpf_trace_printk("PROXY: BAD 5\n");
        return PASS;
    }
    int flow = *active_flow;
    struct dst_server *dst_server = dst_servers.lookup(&flow);
    if (!dst_server) {
        bpf_trace_printk("PROXY: BAD 1\n");
        return PASS;
    }

    struct inhdr orig = *hdr;
    if (GROW_HEAD(ctx, (sizeof(struct proxyhdr) + sizeof(struct udphdr)), data_size)) {
        bpf_trace_printk("PROXY: BAD 2\n");
        return PASS;
    }

    data = (void*)(long)ctx->data;
    data_end = (void*)(long)ctx->data_end;
    struct outhdr *newhdr = data;
    if (data + sizeof(*newhdr) > data_end) {
        bpf_trace_printk("PROXY: BAD 8\n");
        return PASS;
    }

    __be16 newlen = htons(ntohs(orig.ip.tot_len) + sizeof(struct proxyhdr) + sizeof(struct udphdr));


    newhdr->eth = orig.eth;
    memcpy(newhdr->eth.h_dest, orig.eth.h_source, 6);
    memcpy(newhdr->eth.h_source, orig.eth.h_dest, 6);
    newhdr->ip_new = orig.ip;
    newhdr->ip_new.protocol = 0x11;
    newhdr->ip_new.saddr = orig.ip.daddr;
    newhdr->ip_new.daddr = dst_server->addr;
    newhdr->ip_new.tot_len = newlen;
    //newhdr->proxy.orig_protocol = orig.ip.protocol;
    newhdr->proxy.orig_daddr = orig.ip.daddr;
    newhdr->tcp = orig.tcp;
    newhdr->udp.source = 0;
    newhdr->udp.dest = 0;
    newhdr->udp.len = htons(ntohs(newlen) - sizeof(struct iphdr));
    newhdr->udp.check = 0;

    __be16 origproto;
    memcpy(&origproto, &orig.ip.ttl, 2);
    __be16 newproto;
    memcpy(&newproto, &newhdr->ip_new.ttl, 2);

    //newhdr->ip_new.check = incr_check_s(newhdr->ip_new.check,
    //        orig_proto, PROXY_PROTO);

    newhdr->ip_new.check = incr_check_l(newhdr->ip_new.check,
            ntohl(orig.ip.saddr), ntohl(newhdr->ip_new.saddr));
    newhdr->ip_new.check = incr_check_l(newhdr->ip_new.check,
            ntohl(orig.ip.daddr), ntohl(newhdr->ip_new.daddr));
    newhdr->ip_new.check = incr_check_s(newhdr->ip_new.check,
            ntohs(orig.ip.tot_len), ntohs(newhdr->ip_new.tot_len));
    newhdr->ip_new.check = incr_check_s(newhdr->ip_new.check,
            ntohs(origproto), ntohs(newproto));
    //s64 csumdiff = bpf_csum_diff(orig.ip.daddr, 4, newhdr->ip_new.daddr, 4, newhdr->tcp.check);
/*
    newhdr->tcp.check = incr_check_l(newhdr->tcp.check,
            ntohl(orig.ip.daddr), ntohl(newhdr->ip_new.daddr));
    newhdr->tcp.check = incr_check_s(newhdr->tcp.check,
            orig_tcplen, new_tcplen);
    newhdr->tcp.check = incr_add_check_l(newhdr->tcp.check, ntohl(newhdr->proxy.orig_daddr));
*/
    return REFLECT;
}



