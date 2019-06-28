#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include <netinet/ip.h>

enum msg_type {
    HELLO,
    PEER_JOIN,
    INIT_XFER,
    BOUND,
    FINISH_XFER,
    REDIRECT,
    REDIRECTED
};

struct tsock_hdr {
    enum msg_type type;
};

struct hello_msg {
    unsigned int peer_id;
    struct sockaddr_in app_addr;
    struct sockaddr_in ctl_addr;
};

struct redirect_msg {
    int new_fd;
    short n_sport;
    unsigned int orig_peer;
    unsigned int next_peer;
};

struct redirected_msg {
    int new_fd;
};

struct xfer_msg {
    int xfer_id;
};


int create_listening_fd(struct sockaddr_in *addr);
int send_tsock_msg(int fd, enum msg_type type, void *payload, size_t payload_size);
#endif