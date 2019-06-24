#include "logging.h"
#include "tsock.h"
#include "communication.h"

#include <sys/epoll.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

int init_connection(struct tsock_server *self, struct sockaddr_in *addr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr))) {
        perror("Connect");
        return -1;
    }

    struct hello_msg msg = {
        .ctl_addr = self->ctl_addr
    };

    if (send_tsock_msg(fd, HELLO, &msg, sizeof(msg))) {
        logerr("Error sending hello msg");
        return -1;
    }
    return fd;
}

int connect_to_proxy(struct tsock_server *self, struct sockaddr_in *addr) {
    self->proxy_fd = init_connection(self, addr);
    if (self->proxy_fd < 0) {
        logerr("Error connecting to proxy");
        return -1;
    }
    return 0;
};

#define MAX_EPOLL_EVENTS 10
#define MAX_RECV_BUFF 1024

struct peer_args {
    struct tsock_server *self;
    int peer_id;
};

static int add_peer_to_epoll(struct tsock_server *self, int fd, int peer_id) {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u32 = peer_id;
    if (epoll_ctl(self->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        perror("epoll_ctl: adding peer");
        return -1;
    }
    return 0;
}

int handle_peer_join(struct tsock_server *self, struct hello_msg *msg) {
    int fd = init_connection(self, &msg->ctl_addr);
    if (fd < 0) {
        logerr("Initializing peer connection");
        return -1;
    }
    if (self->peers[msg->peer_id]) {
        logerr("Peer %d already joined", msg->peer_id);
        return -1;
    }
    self->peers[msg->peer_id] = fd;
    if (add_peer_to_epoll(self, fd, msg->peer_id)) {
        logerr("Error adding peer %d", msg->peer_id);
        return -1;
    }

    return 0;
}
struct proxy_args {
    struct tsock_server *self;
    struct sockaddr_in *proxy_addr;
};


void *proxy_comm_loop(void *varg) {
    struct proxy_args *arg = varg;
    struct tsock_server *self = arg->self;
    struct sockaddr_in *proxy_addr = arg->proxy_addr;
    if (connect_to_proxy(self, proxy_addr)) {
        self->do_exit = true;
        return NULL;
    }

    ssize_t recvd;
    struct tsock_hdr hdr;
    struct hello_msg msg;
    int err = 0;
    while (!self->do_exit && err == 0) {
        recvd = recv(self->proxy_fd, &hdr, sizeof(hdr), 0);
        if (recvd != sizeof(hdr)) {
            perror("recv from proxy");
            break;
        }
        switch(hdr.type) {
            case PEER_JOIN:
                recvd = recv(self->proxy_fd, &msg, sizeof(msg), 0);
                if (recvd != sizeof(msg)) {
                    perror("Recv msg from proxy");
                    err = -1;
                    break;
                }
                if (handle_peer_join(self, &msg)) {
                    logerr("Handle peer join");
                    err = -1;
                    break;
                }
                break;
            default:
                logerr("Received non PEER_JOIN from proxy: %d", hdr.type);
                err = -1;
                break;
        }
    }
    self->do_exit = true;
    return NULL;
}

int peer_ctl_loop(struct sockaddr_in *ctl_addr, struct sockaddr_in *proxy_addr) {
    struct tsock_server self = {*ctl_addr};
    self.epollfd = epoll_create1(0);
    if (self.epollfd == -1) {
        perror("epoll_create1");
        return -1;
    }
    int ctl_fd = create_listening_fd(ctl_addr);

    struct proxy_args args = {.self = &self, .proxy_addr = proxy_addr};
    int rtn = pthread_create(&self.proxy_thread, NULL, proxy_comm_loop, &args);
    if (rtn) {
        perror("pthread_create");
        return -1;
    }

    struct tsock_hdr hdr;
    struct hello_msg msg;
    while (!self.do_exit) {
        int newfd = accept(ctl_fd, NULL, NULL);
        if (recv(newfd, &hdr, sizeof(hdr), 0) != sizeof(hdr)) {
            perror("recv from newfd");
            self.do_exit = 1;
            break;
        }
        if (hdr.type != HELLO) {
            logerr("Received non-hello type %d", hdr.type);
            self.do_exit = 1;
            break;
        }
        if (recv(newfd, &msg, sizeof(msg), 0) != sizeof(msg)) {
            perror("Recv msg from newfd");
            self.do_exit = 1;
            break;
        }
        if (self.peers[msg.peer_id]) {
            logerr("Peer %d already joined", msg.peer_id);
            self.do_exit = 1;
            break;
        }
        self.peers[msg.peer_id] = newfd;
        if (add_peer_to_epoll(&self, newfd, msg.peer_id)) {
            logerr("Error adding peer %d", msg.peer_id);
        }
    }
    self.do_exit = 1;
    pthread_join(self.proxy_thread, NULL);
    return 0;
}
