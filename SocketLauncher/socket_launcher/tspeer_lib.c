#include "logging.h"
#include "tsock.h"
#include "communication.h"
#include "tspeer_lib.h"
#include "tcp_repair.h"

#include <sys/select.h>
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
#define SOCK_LOC "ipc:///tmp/tspeer/%d"

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


#define MAX_RECV_BUFF 1024

struct peer_args {
    struct tsock_server *self;
    int peer_id;
};

static int get_ip_and_port(struct sockaddr_in *addr, char ip[16], char port[8]) {
    if (inet_ntop(AF_INET, &addr->sin_addr, ip, 16) == NULL) {
        perror("inet_ntop");
        return -1;
    }
    snprintf(port, 8, "%d", ntohs(addr->sin_port));
    return 0;
}


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

static pthread_mutex_t zmq_mutex = PTHREAD_MUTEX_INITIALIZER;
#define ADD_PEER_TEMPLATE "{\"type\": \"add_peer\", \"ip\": \"%s\", \"port\": %s, \"id\": %d}"

static int add_peer(struct sockaddr_in *peer_addr, int peer_id) {
    char ip[16], port[8];
    if (get_ip_and_port(peer_addr, ip, port)) {
        return -1;
    }

    char add_peer_msg[1024];
    size_t n = snprintf(add_peer_msg, sizeof(add_peer_msg), ADD_PEER_TEMPLATE,
                        ip, port, peer_id);
    pthread_mutex_lock(&zmq_mutex);
    zmq_send(requester, add_peer_msg, n, 0);
    loginfo("Adding peer: %s", ip);
    int size = zmq_recv(requester, add_peer_msg, 1024, 0);
    pthread_mutex_unlock(&zmq_mutex);
    add_peer_msg[size] = '\0';
    loginfo("Proxy responded to add peer: %s", add_peer_msg);
    return 0;
}


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

    if (add_peer(&msg.app_addr, msg.peer_id)) {
        return -1;
    }
    return 0;
}
#define ACK_TEMPLATE "{\"type\": \"ack\", \"dst_addr\": \"%s\", \"dst_port\": %s, \"src_port\": %s, \"ack\": %u}"

static int do_ack(struct sockaddr_in *client_addr, struct sockaddr_in *app_addr, uint32_t ackval) {
    char ip[16], port[8];
    if (get_ip_and_port(client_addr, ip, port)) {
        return -1;
    }
    char app_ip[16], app_port[8];
    if (get_ip_and_port(app_addr, app_ip, app_port)) {
        return -1;
    }

    char dup_msg[1025];
    size_t n = snprintf(dup_msg, sizeof(dup_msg), ACK_TEMPLATE,
            ip, port, app_port, htonl(ackval));
    pthread_mutex_lock(&zmq_mutex);
    zmq_send(requester, dup_msg, n, 0);
    int size = zmq_recv(requester, dup_msg, 1024, 0);
    pthread_mutex_unlock(&zmq_mutex);
    dup_msg[size] = '\0';

    loginfo("ZMQ responded to dup: %s", dup_msg);
    return 0;
}

#define X_BLOCK_TEMPLATE "{\"type\": \"%s\", \"ip\": \"%s\", \"src_port\": %s, \"dst_port\": %s, \"towards\": %d}"
static int x_block_delivery(char *x,
                            struct sockaddr_in *client_addr,
                            struct sockaddr_in *app_addr,
                            int towards) {
    char ip[16], port[8];
    if (get_ip_and_port(client_addr, ip, port)) {
        return -1;
    }
    char app_ip[16], app_port[8];
    if (get_ip_and_port(app_addr, app_ip, app_port)) {
        return -1;
    }

    char block_msg[1024];
    size_t n = snprintf(block_msg, sizeof(block_msg),
                        X_BLOCK_TEMPLATE,
                        x, ip, port, app_port, towards);
    pthread_mutex_lock(&zmq_mutex);
    zmq_send(requester, block_msg, n, 0);
    int size = zmq_recv(requester, block_msg, 1024, 0);
    pthread_mutex_unlock(&zmq_mutex);
    block_msg[size] = '\0';

    loginfo("Proxy responded to redirect: %s", block_msg);

    return 0;
}

static int block_delivery(struct sockaddr_in *client_addr, struct sockaddr_in *app_addr, int towards) {
    if (x_block_delivery("block", client_addr, app_addr, towards)) {
        logerr("Error blocking delivery");
        return -1;
    }
    return 0;
}

static int unblock_delivery(struct sockaddr_in *client_addr, struct sockaddr_in *app_addr) {
    if (x_block_delivery("unblock", client_addr, app_addr, -1)) {
        logerr("Error unblocking delivery");
        return -1;
    }
    return 0;
}

#define X_REDIR_TEMPLATE "\"src_addr\": \"%s\", \"src_port\": %s, \"dst_port\": %s"

#define REDIR_TEMPLATE "{\"type\": \"redirect\", \"next_id\": %d, " X_REDIR_TEMPLATE "}"
#define STOP_REDIR_TEMPLATE "{\"type\": \"stop_redirect\", " X_REDIR_TEMPLATE "}"

static int send_redirect(int peer_id,
                         struct sockaddr_in *client_addr,
                         struct sockaddr_in *app_addr) {
    char ip[16], port[8];
    if (get_ip_and_port(client_addr, ip, port)) {
        return -1;
    }
    char app_ip[16], app_port[8];
    if (get_ip_and_port(app_addr, app_ip, app_port)) {
        return -1;
    }
    char redirect_msg[1024];
    size_t n = snprintf(redirect_msg, sizeof(redirect_msg), REDIR_TEMPLATE,
                        peer_id, ip, port, app_port);

    pthread_mutex_lock(&zmq_mutex);
    zmq_send(requester, redirect_msg, n, 0);
    int size = zmq_recv(requester, redirect_msg, 1024, 0);
    pthread_mutex_unlock(&zmq_mutex);
    redirect_msg[size] = '\0';

    loginfo("ZMQ responded to redirect: %s", redirect_msg);

    return 0;
}

static int send_stop_redirect(struct sockaddr_in *client_addr,
                              struct sockaddr_in *app_addr) {
    char ip[16], port[8];
    if (get_ip_and_port(client_addr, ip, port)) {
        return -1;
    }
    char app_ip[16], app_port[8];
    if (get_ip_and_port(app_addr, app_ip, app_port)) {
        return -1;
    }
    char redirect_msg[1024];
    size_t n = snprintf(redirect_msg, sizeof(redirect_msg), STOP_REDIR_TEMPLATE,
                        ip, port, app_port);

    pthread_mutex_lock(&zmq_mutex);
    zmq_send(requester, redirect_msg, n, 0);
    int size = zmq_recv(requester, redirect_msg, 1024, 0);
    pthread_mutex_unlock(&zmq_mutex);
    redirect_msg[size] = '\0';

    loginfo("ZMQ responded to stop_redirect: %s", redirect_msg);

    return 0;
}




struct tsock_server *init_tsock_server(struct sockaddr_in *ctl_addr,
                                       struct sockaddr_in *app_addr,
                                       struct sockaddr_in *proxy_addr,
                                       int id) {
    int ctl_fd = create_listening_fd(ctl_addr, true);
    if (ctl_fd < 0) {
        logerr("Could not create ctl fd");
        return NULL;
    }
    int app_fd = create_listening_fd(app_addr, false);
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
        if (add_peer(&msg.app_addr, msg.peer_id)) {
            logerr("Error adding peer %d to zmq", msg.peer_id);
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

    struct prep_msg msg;
    ssize_t recvd = recv(peer_fd, &msg, sizeof(msg), 0);
    if (recvd != sizeof(msg)) {
        logerr("Weird size prep msg: %zd", recvd);
    }

    if (send_stop_redirect(&msg.client_addr, &server->app_addr)) {
        logerr("Error sending STOP REDIRECT");
       return -1;
    }

    int newfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    //if (setsockopt(newfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt))) {
    //    perror("TCP_NODELAY");
    //    return -1;
    //}

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
    struct sockaddr_in client_addr;
    socklen_t socklen = sizeof(client_addr);
    if (getpeername(newfd, (struct sockaddr*)&client_addr, &socklen)) {
        perror("Getting peer name");
        return -1;
    }

    if (do_ack(&client_addr, &server->app_addr, state.snd.hdr.seq)) {
        logerr("ERROR DUPLICATING PACKETS");
    }

    opt = 0;
    if (setsockopt(newfd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt))) {
        perror("Unsetting TCP_REPAIR");
        return -1;
    }

    int rtn = send_tsock_msg(peer->peer_fd, PREPPED, &msg, sizeof(msg), NULL);
    if (rtn < 0) {
        logerr("Error sending PREPPED msg");
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
    struct prep_msg prep = {
        .orig_fd = fd,
    };
    socklen_t socklen = sizeof(prep.client_addr);
    if (getpeername(fd, (struct sockaddr*)&prep.client_addr, &socklen)) {
        perror("Getting peer name");
        return -1;
    }
    if (block_delivery(&prep.client_addr, &server->app_addr, peer_id)) {
        logerr("Error blocking delivery");
    }

    struct tcp_state state;
    init_tcp_state(&state);
    if (get_tcp_state(fd, &state, 1)) {
        logerr("Error getting TCP state");
        return -1;
    }
    close(fd);

    /*if (pthread_mutex_lock(&server->mutex)) {
        perror("pthread_mutex_lock");
    }*/

    send_tcp_state(peer->peer_fd, &prep, sizeof(prep), &state);
    loginfo("Sent transfer message");

    /*if (pthread_mutex_unlock(&server->mutex)) {
        perror("pthread mutex unlock");
    }*/

    return 0;
}

int handle_redirected(int proxy_fd, struct tsock_server *server) {
    loginfo("Received REDIRECTED\n");
    struct redirect_msg msg;
    ssize_t recvd = recv(proxy_fd, &msg, sizeof(msg), 0);
    if (recvd != sizeof(msg)) {
        logerr("Received weird size redirect msg: %zd", recvd);
        return -1;
    }

    /*
    struct sockaddr_in client_addr;
    socklen_t socklen = sizeof(client_addr);
    if (getpeername(msg.old_fd, (struct sockaddr*)&client_addr, &socklen)) {
        perror("Getting peername for DO_XFER");
        return -1;
    }
    */
    //close(msg.old_fd);

    if (send_stop_redirect(&msg.client_addr, &server->app_addr)) {
        logerr("Error sending STOP REDIRECT");
        return -1;
    }
    
    return 0;
}

static int handle_prepped(struct tsock_peer *peer, struct tsock_server *server) {
    loginfo("Received PREPPED");
    struct prep_msg msg;
    ssize_t recvd = recv(peer->peer_fd, &msg, sizeof(msg), 0);
    if (recvd != sizeof(msg)) {
        logerr("Received weird PREPPED msg: %zd", recvd);
        return -1;
    }

    if (send_redirect(peer->peer_id, &msg.client_addr, &server->app_addr)) {
        return -1;
    }
    if (unblock_delivery(&msg.client_addr, &server->app_addr)) {
        logerr("Error unblocking delivery");
        return -1;
    }
/*
    if (pthread_mutex_unlock(&server->mutex)) {
        perror("pthread_mutex unlock");
    }
*/
    struct redirect_msg re_msg = {
        .old_fd = msg.orig_fd,
        .n_sport = msg.client_addr.sin_port,
        .orig_peer = server->local_id,
        .next_peer = peer->peer_id,
        .client_addr = msg.client_addr
    };

    int rtn = send_tsock_msg(server->proxy_fd, REDIRECT, &re_msg, sizeof(re_msg), NULL);
    if (rtn != 0) {
        logerr("Error sending REDIRECT");
        return -1;
    }
    return 0;
}

#define MAX_EPOLL_EVENTS 1

int tsock_accept(struct tsock_server *server, int timeout_ms) {
    if (!server->running) {
        return -1;
    }
    struct epoll_event events[MAX_EPOLL_EVENTS];
    int n_evt = epoll_wait(server->epollfd, events, MAX_EPOLL_EVENTS, timeout_ms);
    if (n_evt < 0) {
        perror("epoll_wait");
        return -1;
    }
    for (int i=0; i < n_evt; i++) {
        if (!(events[i].events & EPOLLIN)) {
            logerr("Got non-EPOLLIN on %d", events[i].data.u32);
            return -1;
        }

        loginfo("Activity on num %ud", events[i].data.u32);
        if (events[i].data.u32 == MAX_PEERS) {
            int rtn = accept(server->app_fd, NULL, NULL);
            if (rtn < 0) {
                perror("accept on app_fd");
            }
            return rtn;
        }
        int peer_fd;
        struct tsock_peer *peer = NULL;
        if (events[i].data.u32 == MAX_PEERS + 1) {
            loginfo("Activity was proxy");
            peer_fd = server->proxy_fd;
        } else {
            loginfo("Activity was peer");
            peer = &server->peers[events[i].data.u32];
            peer_fd = peer->peer_fd;
        }
        struct tsock_hdr hdr;
        ssize_t recvd = recv(peer_fd, &hdr, sizeof(hdr), 0);
        if (recvd < 0) {
            perror("recv hdr from peer");
            return -2;
        }
        if (recvd != sizeof(hdr)) {
            logerr("Receved weird size message from peer %d: %d", events[i].data.u32, (int)recvd);
            return -2;
        }
        loginfo("Received message of type %d", hdr.type);
        switch(hdr.type) {
            case PEER_JOIN:
                if (handle_peer_join(server, peer_fd)) {
                    logerr("Error handling peer join");
                    return -1;
                }
                break;
            case PREPPED:
                if (handle_prepped(peer, server)) {
                    logerr("Error hanlding PREPPED");
                    return -1;
                }
                break;
            case REDIRECTED:
                if (handle_redirected(peer_fd, server)) {
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

