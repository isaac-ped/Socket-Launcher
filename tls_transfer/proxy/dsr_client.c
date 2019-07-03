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

struct __attribute__((__packed__)) inhdr {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    struct proxyhdr proxy;
    struct tcphdr tcp;
};

struct __attribute__((__packed__)) outhdr {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
};

struct __attribute__((__packed__)) flow {
    __be32 srcaddr;
    __be16 srcport;
    __be16 dstport;
};

BPF_HASH(orig_addrs, struct flow, struct proxyhdr);

#define IP_CSUM_OFF offsetof(struct inhdr, ip) + offsetof(struct iphdr, check)

#define CTX_TYPE struct xdp_md
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

#define SIZE_DIFF (sizeof(struct inhdr) - sizeof(struct outhdr))

int monitor_ingress(CTX_TYPE *ctx) {
    bpf_trace_printk("CLIENT_IN: got pkt\n");
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct inhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("CLIENT_IN: too small\n");
        return PASS;
    }
    if (hdr->eth.h_proto != htons(0x0800)) {
        bpf_trace_printk("CLIENT_IN: Not IP\n");
        return PASS;
    }

    if (hdr->udp.source != 0 || hdr->udp.dest != 0) {
        bpf_trace_printk("CLIENT_IN: Source and dest not 0\n");
        return PASS;
    }

    struct inhdr orig = *hdr;

    if (SHRINK_HEAD(ctx, SIZE_DIFF)) {
        bpf_trace_printk("CLIENT_IN: BAD 1\n");
        return PASS;
    }
    data = (void*)(long)ctx->data;
    data_end= (void*)(long)ctx->data_end;
    struct outhdr *out = data;
    if (data + sizeof(*out) > data_end) {
        bpf_trace_printk("CLIENT_IN: BAD 2\n");
        return PASS;
    }

    __be16 newlen = htons(ntohs(orig.ip.tot_len) - SIZE_DIFF);


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

    bpf_trace_printk("CLIENT_IN: Substd\n");

    struct flow flow = {
        out->ip.saddr, out->tcp.source, out->tcp.dest
    };

    orig_addrs.update(&flow, &orig.proxy);
    return PASS;
}

#undef PASS
#define PASS TC_ACT_OK

int monitor_egress(struct __sk_buff *ctx) {
    bpf_trace_printk("CLIENT_OUT: Got pkt\n");
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct outhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("CLIENT_OUT: Too small\n");
        return PASS;
    }
    if (hdr->eth.h_proto != htons(0x0800)) {
        bpf_trace_printk("CLIENT_OUT: Not IP\n");
        return PASS;
    }

    struct flow flow = {
        hdr->ip.daddr, hdr->tcp.dest, hdr->tcp.source
    };
    struct proxyhdr *orig_addr = orig_addrs.lookup(&flow);
    if (!orig_addr) {
        bpf_trace_printk("CLIENT_OUT: Non matching flow\n");
        return PASS;
    }
    bpf_trace_printk("CLIENT_OUT: Rewriting\n");
    __be32 start_daddr = hdr->ip.daddr;
    __be32 start_saddr = hdr->ip.saddr;

    hdr->ip.daddr = orig_addr->orig_saddr;
    hdr->ip.saddr = orig_addr->orig_daddr;

    hdr->ip.check = incr_check_l(hdr->ip.check,
            ntohl(start_daddr), ntohl(hdr->ip.daddr));
    hdr->ip.check = incr_check_l(hdr->ip.check,
            ntohl(start_saddr), ntohl(hdr->ip.saddr));
    hdr->tcp.check = incr_check_l(hdr->tcp.check,
            ntohl(start_daddr), ntohl(hdr->ip.daddr));
    hdr->tcp.check = incr_check_l(hdr->tcp.check,
            ntohl(start_saddr), ntohl(hdr->ip.saddr));
    hdr->tcp.check -= htons(0x0600);
    return PASS;
}


