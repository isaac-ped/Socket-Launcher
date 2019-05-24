#include <uapi/linux/if_ether.h> //struct ethhdr
#include <uapi/linux/ip.h>  //struct iphdr
#include <uapi/linux/tcp.h> //struct tcphdr
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h> // TC_ACT_OK

#ifndef TARGET_PORT
#error NO TARGET PORT
#else
#define NTARGET_PORT htons(TARGET_PORT)
#endif

#ifndef DST_PORT
#error NO DST_PORT
#else
#define NDST_PORT htons(DST_PORT)
#endif

struct __attribute__((__packed__)) fullhdr {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
};

int rewrite_ingress(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct fullhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("Data too small ing\n");
        return TC_ACT_OK;
    }

    if (hdr->tcp.dest == NTARGET_PORT) {
        hdr->tcp.dest = NDST_PORT;
        bpf_trace_printk("Rewrite ing\n");
    } else {
        bpf_trace_printk("No rewrite ing\n");
    }
    if (bpf_redirect(2, 0) == TC_ACT_REDIRECT) {
        return TC_ACT_REDIRECT;
    }
    return TC_ACT_OK;
}

int rewrite_egress(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct fullhdr *hdr = data;
    if (data + sizeof(*hdr) > data_end) {
        bpf_trace_printk("Too small eg\n");
        return TC_ACT_OK;
    }

    if (hdr->tcp.source == NDST_PORT) {
        bpf_trace_printk("Rewrite eg\n");
        hdr->tcp.source = NTARGET_PORT;
    } else {
        bpf_trace_printk("No rewrite eg\n");
    }

    return TC_ACT_OK;
}
