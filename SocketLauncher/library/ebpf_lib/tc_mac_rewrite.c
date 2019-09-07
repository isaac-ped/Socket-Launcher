#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

#ifndef memset
#define memset(dest, src, n) __builtin_memset((dest),(src),(n))
#endif

#ifndef memset
#define memset(dest, src, n) __builtin_memcpy((dest),(src),(n))
#endif

struct macaddr_t {
    char h_dest[ETH_ALEN];
    u32 ifindex;
};

struct srcaddr_t {
    __be32 saddr;   // IP
    __be16 source;  // Port
};

BPF_ARRAY(mac_array, struct macaddr_t, 2);
BPF_ARRAY(mac_size, u32, 1);
BPF_HASH(mac_indices, struct srcaddr_t, u32);

#define MAX_NOT 128

struct not_t {
    size_t len;
    char msg[MAX_NOT];
};

struct __attribute__((__packed__)) hdr_t {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
};

BPF_PERF_OUTPUT(NOTIFY_EVT);


static inline void notify(struct __sk_buff *skb, const char *str, size_t len) {
    struct not_t n = {};
    n.len = len;
    memcpy(n.msg, str, len > MAX_NOT ? MAX_NOT : len);
    NOTIFY_EVT.perf_submit(skb, &n, sizeof(n));
}

#define NOTIFY(skb, str) \
    notify(skb, str, strlen(str))

int handle_ingress(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    size_t data_len = (long)data_end - (long)data;

    struct hdr_t *hdr = data;

    if (data + sizeof(*hdr) > data_end) {
        NOTIFY(skb, "Data too small");
        return TC_ACT_OK;
    }

    struct srcaddr_t addr = {};
    addr.saddr = hdr->ip.saddr;
    addr.source = hdr->tcp.source;

    int key = 0;
    u32 *n_macs = mac_size.lookup(&key);
    if (n_macs == NULL) {
        NOTIFY(skb, "Shouldn't happen");
        return TC_ACT_OK;
    }

    u32 default_idx = bpf_get_prandom_u32() % *n_macs;

    u32 *idx = mac_indices.lookup_or_init(&addr, &default_idx);

    if (idx == NULL) {
        NOTIFY(skb, "Shouldn't happen");
        return TC_ACT_OK;
    }
    int idx2 = *idx;
    struct macaddr_t *new_addr = mac_array.lookup(&idx2);

    if (new_addr == NULL) {
        NOTIFY(skb, "Shouldn't happen");
        return TC_ACT_OK;
    }

    //hdr->ip.saddr = 0;

    memcpy(hdr->eth.h_dest, new_addr->h_dest, sizeof(new_addr->h_dest));


    NOTIFY(skb, "redirecting");
    if (bpf_redirect(2, 0) == TC_ACT_REDIRECT) {
    //if (bpf_redirect(new_addr->ifindex, 0) == TC_ACT_REDIRECT) {
        NOTIFY(skb, "redirected");
        return TC_ACT_REDIRECT;
    }
    NOTIFY(skb, "NOT REDIR");
    return TC_ACT_OK;

}


