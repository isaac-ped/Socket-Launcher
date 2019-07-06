#include "logging.h"
#include "tsock.h"
#include "communication.h"
#include "tspeer_lib.h"
#include "tcp_repair.h"

#include <unistd.h>
#include <sys/epoll.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <zmq.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>


static void *ctx;
static void *requester;
#define SOCK_LOC "ipc:///tmp/drop_client/%d"

static int init_connection(struct tsock_server *self, struct sockaddr_in *peer_addr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    if (connect(fd, (struct sockaddr*)peer_addr, sizeof(*peer_addr))) {
        perror("Connect");
        return -1;
    }

    struct hello_msg msg = {
        .peer_id  = self->local_id,
        .ctl_addr = self->ctl_addr,
        .app_addr = self->app_addr
    };

    if (send_tsock_msg(fd, HELLO, &msg, sizeof(msg), NULL)) {
        logerr("Error sending hello msg");
        return -1;
    }
    return fd;
}


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
    loginfo("Added peer %d to epoll", peer_id);
    if (epoll_ctl(self->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        perror("epoll_ctl: adding peer");
        return -1;
    }
    return 0;
}

static int connect_to_proxy(struct tsock_server *self, struct sockaddr_in *proxy_addr) {
    self->proxy_fd = init_connection(self, proxy_addr);
    if (self->proxy_fd < 0) {
        logerr("Error connecting to proxy");
        return -1;
    }
    add_peer_to_epoll(self, self->proxy_fd, MAX_PEERS + 1);
    return 0;
};

static int handle_peer_join(struct tsock_server *self, int proxyfd) {
    struct hello_msg msg;
    ssize_t recvd = recv(proxyfd, &msg, sizeof(msg), 0);
    if (recvd != sizeof(msg)) {
        perror("Recv msg from proxy");
        return -1;
    }
    int fd = init_connection(self, &msg.ctl_addr);
    if (fd < 0) {
        logerr("Initializing peer connection");
        return -1;
    }
    loginfo("Initialized connection to peer %d ", msg.peer_id);
    if (self->peers[msg.peer_id].peer_fd) {
        logerr("Peer %d already joined", msg.peer_id);
        return -1;
    }
    self->peers[msg.peer_id].peer_fd = fd;
    self->peers[msg.peer_id].peer_id = msg.peer_id;
    if (add_peer_to_epoll(self, fd, msg.peer_id)) {
        logerr("Error adding peer %d", msg.peer_id);
        return -1;
    }

    return 0;
}

struct tsock_server *init_tsock_server(struct sockaddr_in *ctl_addr,
                                       struct sockaddr_in *app_addr,
                                       struct sockaddr_in *proxy_addr,
                                       int id) {
    int ctl_fd = create_listening_fd(ctl_addr);
    if (ctl_fd < 0) {
        logerr("Could not create ctl fd");
        return NULL;
    }
    int app_fd = create_listening_fd(app_addr);
    if (app_fd < 0) {
        logerr("could not create app fd");
        return NULL;
    }

    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1");
        return NULL;
    }
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u32 = MAX_PEERS;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, app_fd, &ev) == -1) {
        logerr("Error adding app fd to epoll");
        return NULL;
    }

    struct tsock_server *server = calloc(sizeof(*server), 1);
    server->ctl_addr = *ctl_addr;
    server->app_addr = *app_addr;
    server->app_fd = app_fd;
    server->ctl_fd = ctl_fd;
    server->local_id = id;
    server->epollfd = epollfd;

    if (connect_to_proxy(server, proxy_addr)) {
        logerr("Could not connect to proxy");
        free(server);
        return NULL;
    }
    loginfo("Connected to proxy");

    if (pthread_mutex_init(&server->mutex, NULL)) {
        perror("Initializing server mutex");
    }
    return server;
}

static void *peer_ctl_loop(void *vself) {
    struct tsock_server *self = vself;
    /*
    int rtn = pthread_create(&self->proxy_thread, NULL, proxy_comm_loop, self);
    if (rtn) {
        perror("pthread_create");
        return NULL;
    }
    */
    int ctl_fd = self->ctl_fd;

    struct tsock_hdr hdr;
    struct hello_msg msg;
    fd_set ctl_fdset;
    while (!self->do_exit) {
        FD_ZERO(&ctl_fdset);
        FD_SET(ctl_fd, &ctl_fdset);
        struct timeval tv = {.tv_sec = 1};

        if (select(ctl_fd+1, &ctl_fdset, NULL, NULL, &tv) <= 0) {
            continue;
        }
        loginfo("Got activity on ctl fd");
        int newfd = accept(ctl_fd, NULL, NULL);
        if (recv(newfd, &hdr, sizeof(hdr), 0) != sizeof(hdr)) {
            perror("recv from newfd");
            self->do_exit = 1;
            break;
        }
        if (hdr.type != HELLO) {
            logerr("Received non-hello type %d", hdr.type);
            self->do_exit = 1;
            break;
        }
        if (recv(newfd, &msg, sizeof(msg), 0) != sizeof(msg)) {
            perror("Recv msg from newfd");
            self->do_exit = 1;
            break;
        }
        if (self->peers[msg.peer_id].peer_fd) {
            logerr("Peer %d already joined", msg.peer_id);
            self->do_exit = 1;
            break;
        }
        loginfo("Adding peer %d", msg.peer_id);
        self->peers[msg.peer_id].peer_fd = newfd;
        self->peers[msg.peer_id].peer_id = msg.peer_id;
        if (add_peer_to_epoll(self, newfd, msg.peer_id)) {
            logerr("Error adding peer %d", msg.peer_id);
        }
    }
    self->do_exit = 1;
    self->running = false;
    return 0;
}

int start_tsock_server(struct tsock_server *server) {
    if (ctx == NULL) {
        ctx = zmq_ctx_new();
        requester = zmq_socket(ctx, ZMQ_REQ);
        char loc[100];
        snprintf(loc, 100, SOCK_LOC, server->local_id);
        zmq_connect(requester, loc);
    }

    if (server->running) {
        logerr("Server already running");
        return -1;
    }
    server->running = true;
    int rtn = pthread_create(&server->proxy_thread, NULL, peer_ctl_loop, server);
    if (rtn) {
        perror("pthread_create");
        return -1;
    }
    return 0;
}

void stop_tsock_server(struct tsock_server *server) {
    server->do_exit = true;
}

void join_tsock_server(struct tsock_server *server) {
    pthread_join(server->proxy_thread, NULL);
    free(server);
}
static int handle_xfer(struct tsock_peer *peer,
                       struct tsock_server *server) {
    loginfo("Handling init xfer");
    int peer_fd = peer->peer_fd;
    int newfd = socket(AF_INET, SOCK_STREAM, 0);
    struct tcp_state state;
    init_tcp_state(&state);
    if (recv_tcp_state(peer_fd, &state)) {
        logerr("Error receiving tcp state");
        return -1;
    }
    if (set_tcp_state(newfd, &state, &server->app_addr.sin_addr)) {
        logerr("Error setting tcp state");
        return -1;
    }
    int opt = 0;
    if (setsockopt(newfd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt))) {
        perror("Unsetting TCP_REPAIR");
        return -1;
    }
    return newfd;
}

static pthread_mutex_t proxy_mutex = PTHREAD_MUTEX_INITIALIZER;

int tsock_transfer(struct tsock_server *server, int peer_id, int fd) {
    loginfo("Transferring socket");
    struct tsock_peer *peer = &server->peers[peer_id];
    if (peer->peer_fd <= 0) {
        logerr("Peer %d DNE", peer_id);
        return -1;
    }

    struct sockaddr_in peer_addr;
    socklen_t socklen = sizeof(peer_addr);
    if (getpeername(fd, (struct sockaddr*)&peer_addr, &socklen)) {
        perror("Getting peer name");
        return -1;
    }

    struct redirect_msg re_msg = {
        .old_fd = fd,
        .n_sport = peer_addr.sin_port,
        .orig_peer = server->local_id,
        .next_peer = peer_id
    };
    loginfo("Transferring :%d to %d", ntohs(peer_addr.sin_port), peer_id);

    int rtn = send_tsock_msg(server->proxy_fd, REDIRECT, &re_msg, sizeof(re_msg), &proxy_mutex);
    if (rtn < 0) {
        logerr("Error sending REDIRECT msg");
        return -1;
    }

    return 0;
}

int handle_do_xfer(int proxy_fd, struct tsock_server *server) {
    loginfo("Received DO_XFER\n");
    struct redirect_msg msg;
    ssize_t recvd = recv(proxy_fd, &msg, sizeof(msg), 0);
    if (recvd != sizeof(msg)) {
        logerr("Received weird size redirect msg: %zd", recvd);
        return -1;
    }

    struct tsock_peer *peer = &server->peers[msg.next_peer];
    if (peer->peer_fd <= 0) {
        logerr("Peer %d DNE", msg.next_peer);
        return -1;
    }

    struct tcp_state state;
    init_tcp_state(&state);
    if (get_tcp_state(msg.old_fd, &state, 1)) {
        logerr("Error getting tcp state");
        return -1;
    }
    close(msg.old_fd);
    loginfo("Locking mutex (peer)");
    if (pthread_mutex_lock(&server->mutex)) {
        perror("pthread mutex lock");
    }
    int rtn = send_tsock_msg(peer->peer_fd, XFER, NULL, 0, NULL);
    if (rtn < 0) {
        logerr("Error sending INIT_XFER msg");
        return -1;
    }
    if (send_tcp_state(peer->peer_fd, &state)) {
        logerr("Error sending tcp state");
        return -1;
    }

    loginfo("Unlocking mutex (peer)");
    if (pthread_mutex_unlock(&server->mutex)) {
        perror("pthread mutex unlock");
    }
    return 0;
}


int tsock_accept(struct tsock_server *server, int timeout_ms) {
    if (!server->running) {
        return -1;
    }
    struct epoll_event event;
    while (1) {
        int rtn = epoll_wait(server->epollfd, &event, 1, timeout_ms);
        if (rtn < 0) {
            perror("epoll_wait");
            return -1;
        }
        if (rtn == 0) {
            return 0;
        }
        if (!(event.events & EPOLLIN)) {
            logerr("Got non-EPOLLIN on %d", event.data.u32);
            return -1;
        }

        loginfo("Activity on num %ud", event.data.u32);
        if (event.data.u32 == MAX_PEERS) {
            return accept(server->app_fd, NULL, NULL);
        }
        int peer_fd;
        struct tsock_peer *peer = NULL;
        if (event.data.u32 == MAX_PEERS + 1) {
            loginfo("Activity was proxy");
            peer_fd = server->proxy_fd;
        } else {
            loginfo("Activity was peer");
            peer = &server->peers[event.data.u32];
            peer_fd = peer->peer_fd;
        }
        struct tsock_hdr hdr;
        ssize_t recvd = recv(peer_fd, &hdr, sizeof(hdr), 0);
        if (recvd < 0) {
            perror("recv hdr from peer");
            return -1;
        }
        if (recvd != sizeof(hdr)) {
            logerr("Receved weird size message: %d", (int)recvd);
            return -1;
        }
        loginfo("Received message of type %d", hdr.type);
        switch(hdr.type) {
            case PEER_JOIN:
                if (handle_peer_join(server, peer_fd)) {
                    logerr("Error handling peer join");
                    return -1;
                }
                break;
            case DO_XFER:
                if (handle_do_xfer(peer_fd, server)) {
                    logerr("Error handling DO_XFER");
                    return -1;
                }
                break;
            case XFER:;
                int newfd = handle_xfer(peer, server);
                if (newfd < 0) {
                    logerr("Error handling XFER");
                    return -1;
                }
                return newfd;
            default:
                logerr("Received unknown hdr.type=%d", hdr.type);
                return -1;
        }
    }
    return 0;
}

