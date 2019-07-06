#include "logging.h"
#include "communication.h"
#include "tsock.h"

#include <zmq.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>

static void *ctx;
static void *requester;
#define SOCK_LOC "ipc:///tmp/tsproxy/0"

static int get_ip_and_port(struct sockaddr_in *addr, char ip[16], char port[8]) {
    if (inet_ntop(AF_INET, &addr->sin_addr, ip, 16) == NULL) {
        perror("inet_ntop");
        return -1;
    }
    snprintf(port, 8, "%d", ntohs(addr->sin_port));
    return 0;
}

struct peer_info {
    int fd;
    struct sockaddr_in app_addr;
};

struct peer_loop_arg {
    struct peer_info *peers;
    uint32_t self_ip_int;
    char *self_ip;
    int peer_id;
};

static pthread_mutex_t zmq_mutex = PTHREAD_MUTEX_INITIALIZER;
#define ADD_PEER_TEMPLATE "{\"type\": \"add\", \"ip\": \"%s\", \"port\": %s, \"id\": %d}"
static int add_peer(struct sockaddr_in *app_addr, int peer_id) {
    char ip[16], port[8];
    if (get_ip_and_port(app_addr, ip, port)) {
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

#define  REDIRECT_TEMPLATE "{\"type\": \"redirect\", \"orig_id\": %d, \"next_id\": %d, \"n_sport\": %hu}"


static int handle_redirect(struct peer_info *peers, struct redirect_msg *msg, char *self_ip,
                           uint32_t self_ip_int) {
    loginfo("Handling redirect");

    char redirect_msg[1024];
    size_t n = snprintf(redirect_msg, sizeof(redirect_msg), REDIRECT_TEMPLATE,
                        msg->orig_peer, msg->next_peer, msg->n_sport);

    pthread_mutex_lock(&zmq_mutex);
    zmq_send(requester, redirect_msg, n, 0);
    int size = zmq_recv(requester, redirect_msg, 1024, 0);
    pthread_mutex_unlock(&zmq_mutex);
    redirect_msg[size] = '\0';

    loginfo("Proxy responded to redirect: %s", redirect_msg);

    if (msg->orig_peer > MAX_PEERS) {
        logerr("Peer number too high!\n");
        return -1;
    }

    if (send_tsock_msg(peers[msg->orig_peer].fd, DO_XFER, msg, sizeof(*msg), NULL)) {
        logerr("Error sending DO_XFER");
        return -1;
    }

    return 0;
}

static void *peer_loop(void *varg) {
    struct peer_loop_arg *arg = varg;
    int fd = arg->peers[arg->peer_id].fd;

    struct tsock_hdr hdr;
    struct redirect_msg msg;
    ssize_t recvd;
    int err = 0;
    while (err == 0) {
        recvd = recv(fd, &hdr, sizeof(hdr), 0);
        if (recvd < 0) {
            perror("Recv from peer");
            break;
        }
        if (recvd != sizeof(hdr)) {
            logerr("Recived %zd from peer instead of %zu", recvd, sizeof(hdr));
            break;
        }
        switch(hdr.type) {
            case REDIRECT:
                recvd = recv(fd, &msg, sizeof(msg), 0);
                if (recvd < 0) {
                    perror("Recv msg from peer");
                    err = 1;
                    break;
                }
                if (recvd != sizeof(msg)) {
                    logerr("Recived %zd from peer instead of %zu", recvd, sizeof(msg));
                    break;
                }
                if (handle_redirect(arg->peers, &msg, arg->self_ip, arg->self_ip_int)) {
                    logerr("Error handing redirect");
                    err = 1;
                    break;
                }
                break;
            default:
                logerr("Received unknown msg type %d", hdr.type);
                err = 1;
                break;
        }
    }
    close(fd);
    arg->peers[arg->peer_id].fd = 0;
    free(arg);
    return NULL;
}

int proxy_ctl_loop(struct sockaddr_in *ctl_addr) {
    ctx = zmq_ctx_new();
    requester = zmq_socket(ctx, ZMQ_REQ);
    zmq_connect(requester, SOCK_LOC);
    loginfo("Conntected socket to %s\n", SOCK_LOC);

    int ctl_fd = create_listening_fd(ctl_addr);
    char self_ip[16], self_port[8];
    if (get_ip_and_port(ctl_addr, self_ip, self_port)) {
        return -1;
    }

    pthread_t peer_threads[MAX_PEERS] = {};
    struct peer_info peers[MAX_PEERS] = {};

    while (1) {
        int newfd = accept(ctl_fd, NULL, NULL);
        struct tsock_hdr hdr;
        if (recv(newfd, &hdr, sizeof(hdr), 0) != sizeof(hdr)) {
            perror("recv from newfd");
            break;
        }
        if (hdr.type != HELLO) {
            logerr("Received non-hello type message %d", hdr.type);
            break;
        }
        struct hello_msg msg;
        if (recv(newfd, &msg, sizeof(msg), 0) != sizeof(msg)) {
            perror("Recv from newfd");
            break;
        }

        if (peers[msg.peer_id].fd) {
            logerr("Peer %d already joined", msg.peer_id);
            break;
        }

        for (int i=0; i < MAX_PEERS; ++i) {
            if (peers[i].fd) {
                if (send_tsock_msg(peers[i].fd, PEER_JOIN, &msg, sizeof(msg), NULL)) {
                    logerr("Error Forwarding PEER_JOIN");
                    return -1;
                }
                loginfo("Forwarded PEER_JOIN");
            }
        }

        peers[msg.peer_id].fd = newfd;
        peers[msg.peer_id].app_addr = msg.app_addr;

        struct peer_loop_arg *arg = malloc(sizeof(*arg));
        arg->peers = peers;
        arg->peer_id = msg.peer_id;
        arg->self_ip = self_ip;
        arg->self_ip_int = ctl_addr->sin_addr.s_addr;
        if (peer_threads[msg.peer_id]) {
            loginfo("Waiting for existing thread to join");
            pthread_join(peer_threads[msg.peer_id], NULL);
        }
        add_peer(&msg.app_addr, msg.peer_id);

        int rtn = pthread_create(&peer_threads[msg.peer_id], NULL, peer_loop, arg);
        if (rtn) {
            perror("Pthread_create");
            return -1;
        }
    }
    return 0;
}


