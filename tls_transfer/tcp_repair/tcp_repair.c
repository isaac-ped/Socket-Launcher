#include "tcp_repair.h"
#include "logging.h"
#include "communication.h"

#include <sys/uio.h> // readv
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>

static void print_tcp_qstate(struct tcp_qstate *state) {
    printf("\tqueue len: %zu\n", state->hdr.readlen);
    printf("\tseq: %u\n", (state->hdr.seq));
}

void print_tcp_state(struct tcp_state *state) {
    printf("DST ADDR: %s:%d\n", inet_ntoa(state->caddr.dst_addr.sin_addr),
                                htons(state->caddr.dst_addr.sin_port));
    printf("SRC PORT: %d\n", (int)ntohs(state->caddr.src_port));
    printf("RECV QUEUE:\n");
    print_tcp_qstate(&state->rcv);
    printf("SEND QUEUE:\n");
    print_tcp_qstate(&state->snd);
}

static ssize_t recvqmsg(int fd, struct iovec *msg_iov, size_t msg_iovlen) {
    struct msghdr qmsg = {
        .msg_iov = msg_iov,
        .msg_iovlen = msg_iovlen
    };

    ssize_t readlen = recvmsg(fd, &qmsg, MSG_PEEK | MSG_DONTWAIT);
    if (readlen == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        perror("recvmsg");
        return -1;
    }
    struct iovec empty = {"", 0};
    struct msghdr emptyhdr = {
        .msg_iov = &empty,
        .msg_iovlen = 1
    };

    ssize_t sendlen = sendmsg(fd, &emptyhdr, MSG_NOSIGNAL);
    if (sendlen == -1) {
        logerr("ERROR SENDING EMPTY QUEUE");
    }
    loginfo("Sent %zd bytes to queue", sendlen);

    if (qmsg.msg_flags & MSG_TRUNC) {
        logerr("Queue truncated");
        return -1;
    }
    return readlen;
}

static int get_tcp_qstate(int fd, struct tcp_qstate *qstate, int qspec) {
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &qspec, sizeof(qspec))) {
        perror("Setting TCP_REPAIR_QUEUE");
        return -1;
    }
    if ((qstate->hdr.readlen = recvqmsg(fd, qstate->msg_iov, qstate->hdr.msg_iovlen)) == -1 ) {
        logerr("recvqmsg");
        return -1;
    }
    loginfo("Sent qlen %zu", qstate->hdr.readlen);

    qstate->msg_iov[0].iov_len =  qstate->hdr.readlen;
    socklen_t seqlen = sizeof(qstate->hdr.seq);
    if (getsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, &qstate->hdr.seq, &seqlen)) {
        perror("Getting TCP_QUEUE_SEQ");
        return -1;
    }
    return 0;
}

int get_tcp_state(int fd, struct tcp_state *state, int init) {
    if (init != 0) {
        int opt = 1;
        if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt))) {
            perror("Setting TCP_REPAIR");
            return -1;
        }
    }
    int opt = 1;
    if (setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt))) {
        perror("SETTING TCP_CORK");
    }


    socklen_t socklen = sizeof(state->caddr.dst_addr);
    if (getpeername(fd, (struct sockaddr*)&state->caddr.dst_addr, &socklen)) {
        perror("Getting peer name");
        return -1;
    }
    struct sockaddr_in src_addr;
    if (getsockname(fd, (struct sockaddr*)&src_addr, &socklen)) {
        perror("Getting sockname");
        return -1;
    }
    state->caddr.src_port = src_addr.sin_port;
    if (get_tcp_qstate(fd, &state->rcv, TCP_RECV_QUEUE)) {
        logerr("Getting TCP_RECV_QUEUE state");
        return -1;
    }
    if (get_tcp_qstate(fd, &state->snd, TCP_SEND_QUEUE)) {
        logerr("Getting TCP_SEND_QUEUE state");
        return -1;
    }
    return 0;
}
static ssize_t sendqmsg(int fd, struct iovec *msg_iov, size_t msg_iovlen) {
    struct msghdr qmsg = {
        .msg_iov = msg_iov,
        .msg_iovlen = msg_iovlen
    };

    ssize_t sendlen = sendmsg(fd, &qmsg, MSG_NOSIGNAL);
    if (sendlen == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        perror("recvmsg");
        return -1;
    }
    if (qmsg.msg_flags & MSG_TRUNC) {
        logerr("Queue truncated");
        return -1;
    }
    return sendlen;
}

#define MAX_IOV_LEN 2048
#define MAX_MSG_IOVLEN 1

static int set_tcp_qstate_iov(int fd, struct tcp_qstate *qstate, int qspec) {
    if (qstate->hdr.readlen == 0) {
        return 0;
    }
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &qspec, sizeof(qspec))) {
        perror("Error setting TCP_REPAIR_QUEUE");
        return -1;
    }
    if ((sendqmsg(fd, qstate->msg_iov, qstate->hdr.msg_iovlen)) != qstate->msg_iov[0].iov_len) {
        logerr("Error sending qmsg for setting state");
        return -1;
    }
    loginfo("Repaired queue with %d bytes", (int) qstate->msg_iov[0].iov_len);
    return 0;
}
static int set_tcp_qstate_seq(int fd, struct tcp_qstate *qstate, int qspec) {

    if (setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &qspec, sizeof(qspec))) {
        perror("Error setting TCP_REPAIR_QUEUE");
        return -1;
    }

    if (setsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, &qstate->hdr.seq, sizeof(qstate->hdr.seq))) {
        perror("Setting TCP_QUEUE_SEQ");
        return -1;
    }
    return 0;
}

int activate_socket(int fd) {
    int opt = 0;
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt))) {
        perror("Unsetting TCP_REPAIR");
        return -1;
    }
    return 0;
}

int set_tcp_state(int fd, struct tcp_state *state, struct in_addr *local_addr) {
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Setting REUSEADDR");
        return -1;
    }
    opt = 1;
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt))) {
        perror("Setting TCP_REPAIR");
        return -1;
    }
    opt = 1;

    struct sockaddr_in srcaddr = {
        .sin_family = AF_INET,
        .sin_port = state->caddr.src_port,
        .sin_addr = *local_addr
    };
    if (bind(fd, (struct sockaddr*)&srcaddr, sizeof(srcaddr))) {
        logerr("Could not bind to port: %d!", (int)htons(srcaddr.sin_port));
        perror("bind repaired");
        return -1;
    }

    state->rcv.hdr.seq -= state->rcv.hdr.readlen;
    state->snd.hdr.seq -= state->snd.hdr.readlen;
    if (set_tcp_qstate_seq(fd, &state->rcv, TCP_RECV_QUEUE)) {
        logerr("Error setting TCP_RECV_QUEUE iov");
        return -1;
    }
    if (set_tcp_qstate_seq(fd, &state->snd, TCP_SEND_QUEUE)) {
        logerr("Error setting TCP_SEND_QUEUE iov");
        return -1;
    }

    if (connect(fd, (struct sockaddr*)&state->caddr.dst_addr, sizeof(state->caddr.dst_addr))) {
        perror("Error connecting repaired socket");
        logerr("Couldn't connect to %d:%u", state->caddr.dst_addr.sin_addr.s_addr, ntohs(state->caddr.dst_addr.sin_port));
        return -1;
    }

    if (set_tcp_qstate_iov(fd, &state->rcv, TCP_RECV_QUEUE)) {
        logerr("Error setting TCP_RECV_QUEUE iov");
        return -1;
    }

    if (set_tcp_qstate_iov(fd, &state->snd, TCP_SEND_QUEUE)) {
        logerr("Error setting TCP_SEND_QUEUE iov");
        return -1;
    }
    return 0;
}


static void init_tcp_qstate(struct tcp_qstate *state) {
    state->msg_iov = malloc(sizeof(struct iovec) * MAX_MSG_IOVLEN);
    for (int i=0; i < MAX_MSG_IOVLEN; ++i) {
        state->msg_iov[i].iov_base = malloc(MAX_IOV_LEN);
        state->msg_iov[i].iov_len = MAX_IOV_LEN;
    }
    state->hdr.msg_iovlen = MAX_MSG_IOVLEN;
}

void init_tcp_state(struct tcp_state *state) {
    init_tcp_qstate(&state->rcv);
    init_tcp_qstate(&state->snd);
}

static void destroy_tcp_qstate(struct tcp_qstate *state) {
    for (int i=0; i < MAX_MSG_IOVLEN; ++i) {
        free(state->msg_iov[i].iov_base);
    }
    free(state->msg_iov);
}

void destroy_tcp_state(struct tcp_state *state) {
    destroy_tcp_qstate(&state->rcv);
    destroy_tcp_qstate(&state->snd);
}

static int __attribute__((__unused__)) send_tcp_qstate(int fd, struct tcp_qstate *qstate) {
    ssize_t sent;
    if ((sent = send(fd, &qstate->hdr, sizeof(qstate->hdr), 0)) != sizeof(qstate->hdr)) {
        perror("Error sending qstate hdr");
        return -1;
    }
    if ((sent = writev(fd, qstate->msg_iov, qstate->hdr.msg_iovlen)) != qstate->msg_iov[0].iov_len) {
        perror("Error writev'ing");
        logerr("Wrote %zd/%zu", sent, qstate->hdr.readlen);
        return -1;
    }
    return 0;
}

int send_tcp_state(int fd, void *prefix, size_t prefix_size, struct tcp_state *state) {
    ssize_t sent;
    enum msg_type type = XFER;

    struct iovec iov[] = {
        {&type, sizeof(type)},
        {prefix, prefix_size},
        {&state->caddr, sizeof(state->caddr)},
        {&state->rcv.hdr, sizeof(state->rcv.hdr)},
        {state->rcv.msg_iov[0].iov_base, state->rcv.msg_iov[0].iov_len},
        {&state->snd.hdr, sizeof(state->snd.hdr)},
        {state->snd.msg_iov[0].iov_base, state->snd.msg_iov[0].iov_len}
    };

    size_t tot_size = prefix_size + sizeof(type) + sizeof(state->caddr) + \
                      sizeof(state->rcv.hdr) + state->rcv.msg_iov[0].iov_len + \
                      sizeof(state->snd.hdr) + state->snd.msg_iov[0].iov_len;

    struct msghdr hdr = {
        .msg_iov = iov,
        .msg_iovlen = 7
    };

    if ((sent = sendmsg(fd, &hdr, 0)) != tot_size) {
        perror("Error sendmsging");
        logerr("Wrote %zd/%zu", sent, tot_size);
    }

    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt))) {
        perror("QUICKACK");
        return -1;
    }
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt))) {
        perror("TCP_NODELAY");
        return -1;
    }
    return 0;
/*
    if ((sent = send(fd, &state->caddr, sizeof(state->caddr), 0))
            != sizeof(state->caddr)) {
        perror("Sending dst_addr and src_port");
        return -1;
    }

    if (send_tcp_qstate(fd, &state->rcv)) {
        logerr("Error sending rcv state");
        return -1;
    }
    if (send_tcp_qstate(fd, &state->snd)) {
        logerr("Error sending snd state");
        return -1;
    }
    */
    return 0;
}


static int recv_tcp_qstate(int fd, struct tcp_qstate *qstate) {
    ssize_t rcvd;
    if ((rcvd = recv(fd, &qstate->hdr, sizeof(qstate->hdr), 0)) != sizeof(qstate->hdr)) {
        perror("Error receiving qstate hdr");
        return -1;
    }

    qstate->msg_iov[0].iov_len = qstate->hdr.readlen;
    loginfo("Readlen: %zu", qstate->hdr.readlen);

    if (qstate->msg_iov[0].iov_len > 0) {
        if ((rcvd = readv(fd, qstate->msg_iov, qstate->hdr.msg_iovlen)) < 0) {
            perror("Error readv'ing");
            return -1;
        }
        loginfo("Readv'd %zd bytes", rcvd);
    }
    return 0;
}

int recv_tcp_state(int fd, struct tcp_state *state) {
    ssize_t rcvd;
    if ((rcvd = recv(fd, &state->caddr, sizeof(state->caddr), 0))
            != sizeof(state->caddr)) {
        perror("Error receiving socket addr");
        return -1;
    }

    if (recv_tcp_qstate(fd, &state->rcv)) {
        logerr("Error recving rcv state");
        return -1;
    }
    if (recv_tcp_qstate(fd, &state->snd)) {
        logerr("Error recving snd state");
        return -1;
    }
    return 0;
}
