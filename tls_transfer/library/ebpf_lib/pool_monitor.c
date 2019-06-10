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

int monitor_ingress(struct __sk_buff *skb) {
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
