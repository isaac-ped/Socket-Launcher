#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include <netinet/ip.h>

enum msg_type {
    HELLO,
    PEER_JOIN,
    PREP,
    PREPPED,
    REDIRECT,
    REDIRECTED,
    XFER
};

struct tsock_hdr {
    enum msg_type type;
};

struct hello_msg {
    unsigned int peer_id;
    struct sockaddr_in app_addr;
    struct sockaddr_in ctl_addr;
};

struct prep_msg {
    int orig_fd;
    struct sockaddr_in client_addr;
};

struct redirect_msg {
    int old_fd;
    short n_sport;
    unsigned int orig_peer;
    unsigned int next_peer;
};

struct undrop_msg {
    struct sockaddr_in src_addr;
    uint16_t dst_port;
};

struct redirected_msg {
    int new_fd;
};

struct xfer_msg {
    int xfer_id;
};


int create_listening_fd(struct sockaddr_in *addr);
int send_tsock_msg(int fd, enum msg_type type, void *payload, size_t payload_size, pthread_mutex_t *mutex);
#endif
