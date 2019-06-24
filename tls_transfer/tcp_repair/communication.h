#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include <netinet/ip.h>

enum msg_type {
    HELLO,
    PEER_JOIN,
    TRANSFER_SEQ,
    BOUND,
    TRANSFER_STATE,
    REDIRECT
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
    short n_sport;
    unsigned int orig_peer;
    unsigned int next_peer;
};

int create_listening_fd(struct sockaddr_in *addr);
int send_tsock_msg(int fd, enum msg_type type, void *payload, size_t payload_size);
#endif
