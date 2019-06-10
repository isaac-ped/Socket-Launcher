#include <uapi/linux/if_ether.h> //struct ethhdr
#include <uapi/linux/ip.h>  //struct iphdr
#include <uapi/linux/tcp.h> //struct tcphdr
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h> // TC_ACT_OK

///////// POOL MONITOR

struct __attribute__((__packed__)) fullhdr {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
};

struct port_range {
    u16 start;
    u16 stop;
};

struct __attribute__((__packed__)) monitored_socket {
    __be32 addr;
    u16 port;
    u32 seq;
    u32 ack;
};

struct __attribute__((__packed__)) monitored_address {
    __be32 addr;
    u16 dest_port;
};

BPF_HASH(port_ranges, struct monitored_address, struct port_range);

#define MAX_POOL_SIZE 16

BPF_PERF_OUTPUT(add_to_pool);
BPF_PERF_OUTPUT(rm_from_pool);
BPF_PERF_OUTPUT(clear_pool);

static int monitor_ingress(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    bpf_trace_printk("PM: Got Packet\n");

    struct fullhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("PM: Too small\b");
        return TC_ACT_OK;
    }

    struct monitored_address key = {
        .addr = hdr->ip.saddr,
        .dest_port = hdr->tcp.dest
    };

    struct port_range *pr = port_ranges.lookup(&key);

    if (!pr) {
        bpf_trace_printk("PM: Not relevant\n");
        return TC_ACT_OK;
    }

    u16 port = ntohs(hdr->tcp.source);

    if (port >= pr->start && port <= pr->stop) {
        struct monitored_socket sock = {
            .addr = ntohl(hdr->ip.saddr),
            .port = port,
            .seq = ntohl(hdr->tcp.seq),
            .ack = ntohl(hdr->tcp.ack_seq)
        };

        bpf_trace_printk("Notified\n");

        if (sock.ack == 0) {
            clear_pool.perf_submit(skb, &sock, sizeof(sock));
        } else if (!hdr->tcp.fin && !hdr->tcp.rst) {
            add_to_pool.perf_submit(skb, &sock, sizeof(sock));
        } else {
            rm_from_pool.perf_submit(skb, &sock, sizeof(sock));
        }
    } else {
        bpf_trace_printk("Port is %d, range is: %d-%d\n", port, pr->start, pr->stop);
    }

    return TC_ACT_OK;
}

//////// SOURCE REWRITER

struct __attribute__((__packed__)) proposed_rewrite {
    __be32 addr_new;
    __be16 port_new;
    __be32 seq_new;
    __be32 ack_new;
};

struct __attribute__((__packed__)) rewrite_key {
    __be32 addr;
    __be16 port;
};

struct __attribute__((__packed__)) active_rewrite {
    struct proposed_rewrite rewrite;
    s64 seq_diff;
    s64 ack_diff;
};

BPF_HASH(proposed_in, struct rewrite_key, struct proposed_rewrite);
BPF_HASH(active_in, struct rewrite_key, struct active_rewrite);
BPF_HASH(active_out, struct rewrite_key, struct active_rewrite);

BPF_PERF_OUTPUT(ingress_events);
BPF_PERF_OUTPUT(egress_events);

static __be32 apply_offset(__be32 *orig, s64 off) {
    bpf_trace_printk("Seq changing from %lu by %lld\n", htonl(*orig), off);
    s64 orig2 = (s64)ntohl(*orig);
    orig2 -= off;
    orig2 += ((s64)1) << 32;
    orig2 %= ((s64)1) << 32;
    *orig = htonl((__be32)orig2);
    bpf_trace_printk("Seq changed to %lu\n", htonl(*orig));
    return *orig;
}

#define TCP_CSUM_OFF offsetof(struct fullhdr, tcp) + offsetof(struct tcphdr, check)

int rewrite_ingress(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct fullhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("IN:: Data too small\n");
        return TC_ACT_OK;
    }

    struct rewrite_key key = {
        .addr = hdr->ip.saddr,
        .port = hdr->tcp.source
    };

    struct active_rewrite *a_rewrite = active_in.lookup(&key);
    if (!a_rewrite) {
        bpf_trace_printk("IN:: No active, attempting proposal\n");
        struct proposed_rewrite *p_rewrite = proposed_in.lookup(&key);
        if (!p_rewrite) {
            bpf_trace_printk("IN:: No proposal, returning TC_ACT_OK\n");
            return monitor_ingress(skb);
        }
        bpf_trace_printk("IN:: Found proposal\n");
        bpf_trace_printk("New IP:: %ld-> %ld\n", key.addr, p_rewrite->addr_new);
        bpf_trace_printk("New seq:: %ld -> %ld\n", hdr->tcp.seq, p_rewrite->seq_new);
        struct active_rewrite new_rewrite = {
            .rewrite = *p_rewrite,
            .seq_diff = (s64)ntohl(hdr->tcp.seq) - (s64)ntohl(p_rewrite->seq_new),
            .ack_diff = (s64)ntohl(hdr->tcp.ack_seq) - (s64)ntohl(p_rewrite->ack_new),
        };

        a_rewrite = active_in.lookup_or_init(&key, &new_rewrite);

        struct rewrite_key out_key = {
            .addr = p_rewrite->addr_new,
            .port = p_rewrite->port_new
        };

        struct active_rewrite out_rewrite = {
            .rewrite = {
                .addr_new = hdr->ip.saddr,
                .port_new = hdr->tcp.source,
            },
            .seq_diff = -new_rewrite.ack_diff,
            .ack_diff = -new_rewrite.seq_diff,
        };

        active_out.update(&out_key, &out_rewrite);
    }

    if (a_rewrite) {
        __be32 orig_seq = hdr->tcp.seq;
        __be32 new_seq = apply_offset(&hdr->tcp.seq, a_rewrite->seq_diff);

        __be32 orig_ack = hdr->tcp.ack_seq;
        __be32 new_ack = apply_offset(&hdr->tcp.ack_seq, a_rewrite->ack_diff);

        __be32 orig_addr = hdr->ip.saddr;
        __be32 new_addr = a_rewrite->rewrite.addr_new;

        __be16 orig_sport = hdr->tcp.source;
        __be16 new_sport = a_rewrite->rewrite.port_new;

        hdr->ip.saddr = new_addr;
        hdr->tcp.source = new_sport;
        __be32 csum = hdr->tcp.check;

        bpf_l3_csum_replace(skb, offsetof(struct fullhdr, ip) + offsetof(struct iphdr, check),
                            orig_addr, new_addr, 4);


        u64 rtn = bpf_l4_csum_replace(skb, TCP_CSUM_OFF,
                            orig_addr, new_addr, BPF_F_PSEUDO_HDR | sizeof(new_addr));
        if (rtn != 0) {
            bpf_trace_printk("IN: Csum replace error: %d\n", (int)rtn);
        }
        rtn = bpf_l4_csum_replace(skb, TCP_CSUM_OFF,
                            orig_sport, new_sport, sizeof(new_sport));
        if (rtn != 0) {
            bpf_trace_printk("IN: Csum replace error: %d\n", (int)rtn);
        }

        rtn = bpf_l4_csum_replace(skb, TCP_CSUM_OFF,
                            orig_seq, new_seq, sizeof(new_seq));
        if (rtn != 0) {
            bpf_trace_printk("IN: Csum replace error: %d\n", (int)rtn);
        }

        rtn = bpf_l4_csum_replace(skb, TCP_CSUM_OFF,
                            orig_ack, new_ack, sizeof(new_ack));
        if (rtn != 0) {
            bpf_trace_printk("IN: Csum replace error: %d\n", (int)rtn);
        }

        bpf_trace_printk("IN:: Rewritten\n");
    } else {
        bpf_trace_printk("IN:: Not rewriting\n");
    }

    return monitor_ingress(skb);
}

int rewrite_egress(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    bpf_trace_printk("OUT:: Got packet\n");

    struct fullhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("OUT:: Data too small \n");
        return TC_ACT_OK;
    }

    struct rewrite_key key = {
        .addr = hdr->ip.daddr,
        .port = hdr->tcp.dest
    };

    struct active_rewrite *a_rewrite = active_out.lookup(&key);

    if (a_rewrite) {

        __be32 orig_seq = hdr->tcp.seq;
        __be32 new_seq  = apply_offset(&hdr->tcp.seq, a_rewrite->seq_diff);

        __be32 orig_ack = hdr->tcp.ack_seq;
        __be32 new_ack  = apply_offset(&hdr->tcp.ack_seq, a_rewrite->ack_diff);

        __be32 orig_addr = hdr->ip.daddr;
        __be32 new_addr  = a_rewrite->rewrite.addr_new;

        __be16 orig_dport = hdr->tcp.dest;
        __be16 new_dport  = a_rewrite->rewrite.port_new;

        hdr->ip.daddr = new_addr;
        hdr->tcp.dest = new_dport;
        bpf_l3_csum_replace(skb, offsetof(struct fullhdr, ip) + offsetof(struct iphdr, check),
                            orig_addr, new_addr, 4);
        bpf_l4_csum_replace(skb, offsetof(struct fullhdr, tcp) + offsetof(struct tcphdr, check),
                            orig_addr, new_addr, sizeof(new_addr) | BPF_F_PSEUDO_HDR);
        bpf_l4_csum_replace(skb, offsetof(struct fullhdr, tcp) + offsetof(struct tcphdr, check),
                            orig_dport, new_dport, sizeof(new_dport));
        bpf_l4_csum_replace(skb, offsetof(struct fullhdr, tcp) + offsetof(struct tcphdr, check),
                            orig_ack, new_ack, sizeof(new_ack));
        bpf_l4_csum_replace(skb, offsetof(struct fullhdr, tcp) + offsetof(struct tcphdr, check),
                            orig_seq, new_seq, sizeof(new_seq));

        bpf_trace_printk("OUT:: Rewriting\n");
    } else {
        bpf_trace_printk("OUT:: Not rewriting\n");
    }

    return TC_ACT_OK;
}
