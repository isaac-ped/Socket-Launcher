#include <uapi/linux/if_ether.h> //struct ethhdr
#include <uapi/linux/ip.h>  //struct iphdr
#include <uapi/linux/tcp.h> //struct tcphdr
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h> // TC_ACT_OK


struct __attribute__((__packed__)) fullhdr {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
};

struct __attribute__((__packed__)) addr_tuple {
    // IP
    //__u8 protocol;
    __be32 saddr;
    // TCP/UDP
    __be16 source;
};

struct seq_rewrite {
    __be32 seq_start;
    __be32 seq_offset;
    __be32 ack_start;
    __be32 ack_offset;
    bool seq_offset_set;
    bool ack_offset_set;
};

BPF_PERF_OUTPUT(ingress_events);
BPF_PERF_OUTPUT(egress_events);

BPF_HASH(seq_table, struct addr_tuple, struct seq_rewrite);

int change_ingress(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct fullhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("Data too small \n");
        return TC_ACT_OK;
    }

    struct addr_tuple addr = {
        //.protocol = hdr->ip.protocol,
        .saddr = hdr->ip.saddr,
        //.daddr = hdr->ip.daddr,
        .source = hdr->tcp.source,
        //.dest = hdr->tcp.dest
    };
    struct seq_rewrite *rewrite = seq_table.lookup(&addr);

    if (rewrite == NULL) {
        bpf_trace_printk("Not in table\n");
        bpf_trace_printk("%u:%d", addr.saddr,(int) addr.source);
        return TC_ACT_OK;
    }

    if (!rewrite->seq_offset_set) {
        rewrite->seq_offset = rewrite->seq_start - hdr->tcp.seq;
        rewrite->seq_offset_set = 1;
        rewrite->ack_offset = rewrite->ack_start - hdr->tcp.ack_seq;
        rewrite->ack_offset_set = 1;
    }

    struct seq_rewrite orig = {};
    orig.seq_start = ntohl(hdr->tcp.seq);
    orig.ack_start = ntohl(hdr->tcp.ack_seq);
    orig.seq_offset = rewrite->seq_offset;
    orig.ack_offset = rewrite->ack_offset;

    ingress_events.perf_submit(skb, &orig, sizeof(orig));


    hdr->tcp.seq += rewrite->seq_offset;
    if (rewrite->ack_offset_set)
        hdr->tcp.ack_seq += rewrite->ack_offset;

    return TC_ACT_OK;
}

int change_egress(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct fullhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("Data too small \n");
        return TC_ACT_OK;
    }

    struct addr_tuple addr = {
        //.protocol = hdr->ip.protocol,
        .saddr = hdr->ip.daddr,
        //.daddr = hdr->ip.daddr,
        .source = hdr->tcp.dest,
        //.dest = hdr->tcp.dest
    };

    struct seq_rewrite *rewrite = seq_table.lookup(&addr);

    if (rewrite == NULL) {
        bpf_trace_printk("Not in table\n");
        return TC_ACT_OK;
    }

    struct seq_rewrite orig = {};
    orig.seq_start = hdr->tcp.seq;
    orig.ack_start = hdr->tcp.ack_seq;
    orig.seq_offset = rewrite->seq_offset;
    orig.ack_offset = rewrite->ack_offset;

    egress_events.perf_submit(skb, &orig, sizeof(orig));


    if (!rewrite->seq_offset_set) {
        bpf_trace_printk("Offset not set on egress!\n");
        return TC_ACT_OK;
    }

    hdr->tcp.seq -= rewrite->ack_offset;
    hdr->tcp.ack_seq -= rewrite->seq_offset;
    return TC_ACT_OK;
}
