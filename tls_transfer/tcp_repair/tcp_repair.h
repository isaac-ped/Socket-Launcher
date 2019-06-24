#ifndef _TCP_REPAIR_H
#define _TCP_REPAIR_H

#include <unistd.h>
#include <inttypes.h>
#include <netinet/in.h>

struct tcp_qstate_hdr {
    size_t readlen;
    uint32_t seq;
    size_t msg_iovlen;
};

struct tcp_qstate {
    struct tcp_qstate_hdr hdr;
    struct iovec *msg_iov;
};

struct connection_addr {
    struct sockaddr_in dst_addr;
    in_port_t src_port;
};

struct tcp_state {
    struct connection_addr caddr;
    struct tcp_qstate rcv;
    struct tcp_qstate snd;
};

int get_tcp_state(int fd, struct tcp_state *state);

int set_tcp_state(int fd, struct tcp_state *state);

void init_tcp_state(struct tcp_state *state);

void destroy_tcp_state(struct tcp_state *state);

void print_tcp_state(struct tcp_state *state);

int send_tcp_state(int fd, struct tcp_state *state);

int recv_tcp_state(int fd, struct tcp_state *state);

#endif
