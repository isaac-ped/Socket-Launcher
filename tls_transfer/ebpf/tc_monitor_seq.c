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

struct seq_values {
    __be32 seq;
    __be32 ack;
};

BPF_HASH(seqs, struct addr_tuple, struct seq_values);

int monitor_ingress(struct __sk_buff *skb) {
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
        .source = ntohs(hdr->tcp.source)
        //.dest = hdr->tcp.dest
    };

    struct seq_values seq_val = {
        .seq = ntohl(hdr->tcp.seq),
        .ack = ntohl(hdr->tcp.ack_seq)
    };

    seqs.update(&addr, &seq_val);
    return TC_ACT_OK;
}
