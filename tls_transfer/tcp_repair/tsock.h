#ifndef _TSOCK_H_
#define _TSOCK_H_
#include <netinet/ip.h>
#include <stdbool.h>

#define MAX_PEERS 16
#define MAX_ACTIVE_TRANSFERS 128

struct tsock_peer {
    int peer_fd;
    int peer_id;
    int active_transfers[MAX_ACTIVE_TRANSFERS];
};


struct tsock_server {
    struct sockaddr_in ctl_addr;
    struct sockaddr_in app_addr;
    int app_fd;
    int ctl_fd;
    int local_id;
    bool do_exit;
    int proxy_fd;
    pthread_t ctl_thread;
    pthread_t proxy_thread;
    struct tsock_peer peers[MAX_PEERS];
    int active_transfers[MAX_ACTIVE_TRANSFERS];
    int max_active_xfer;
    int epollfd;
    bool running;
    pthread_mutex_t mutex;
};

int tx_tsock(int fd, int peerfd);
int rx_tsock(int ctl_fd);

#endif
