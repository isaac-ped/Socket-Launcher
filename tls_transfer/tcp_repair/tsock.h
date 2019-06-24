#ifndef _TSOCK_H_
#define _TSOCK_H_
#include <netinet/ip.h>
#include <stdbool.h>

#define MAX_PEERS 16

struct tsock_server {
    struct sockaddr_in ctl_addr;
    bool do_exit;
    int proxy_fd;
    pthread_t proxy_thread;
    int peers[MAX_PEERS];
    int epollfd;
};

int tx_tsock(int fd, int peerfd);
int rx_tsock(int ctl_fd);

#endif
