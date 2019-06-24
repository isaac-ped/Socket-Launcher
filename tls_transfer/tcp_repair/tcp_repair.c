#include "tcp_repair.h"
#include "logging.h"

#include <sys/uio.h> // readv
#include <stdio.h>
#include <sys/socket.h>
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
        return -1;
    }
    qstate->msg_iov[0].iov_len =  qstate->hdr.readlen;
    socklen_t seqlen = sizeof(qstate->hdr.seq);
    if (getsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, &qstate->hdr.seq, &seqlen)) {
        perror("Getting TCP_QUEUE_SEQ");
        return -1;
    }
    return 0;
}

int get_tcp_state(int fd, struct tcp_state *state) {
    int opt = 1;
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt))) {
        perror("Setting TCP_REPAIR");
        return -1;
    }
    if (get_tcp_qstate(fd, &state->rcv, TCP_RECV_QUEUE)) {
        logerr("Getting TCP_RECV_QUEUE state");
        return -1;
    }
    if (get_tcp_qstate(fd, &state->snd, TCP_SEND_QUEUE)) {
        logerr("Getting TCP_SEND_QUEUE state");
        return -1;
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
    if (close(fd)) {
        perror("close");
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

int set_tcp_state(int fd, struct tcp_state *state) {
    int opt = 1;
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt))) {
        perror("Setting TCP_REPAIR");
        return -1;
    }
    opt = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setting REUSEADDR");
        return -1;
    }

    struct sockaddr_in srcaddr = {
        .sin_family = AF_INET,
        .sin_port = state->caddr.src_port,
    };
    if (inet_aton("14.0.0.1", &srcaddr.sin_addr) == 0) {
        perror("inet_aton");
        return -1;
    }

    state->rcv.hdr.seq -= state->rcv.hdr.readlen;
    if (set_tcp_qstate_seq(fd, &state->rcv, TCP_RECV_QUEUE)) {
        logerr("Error setting TCP_RECV_QUEUE iov");
        return -1;
    }
    if (set_tcp_qstate_seq(fd, &state->snd, TCP_SEND_QUEUE)) {
        logerr("Error setting TCP_SEND_QUEUE iov");
        return -1;
    }
    if (bind(fd, (struct sockaddr*)&srcaddr, sizeof(srcaddr))) {
        perror("bind repaired");
        return -1;
    }
    if (connect(fd, (struct sockaddr*)&state->caddr.dst_addr, sizeof(state->caddr.dst_addr))) {
        perror("Error connecting repaired socket");
    }
    if (set_tcp_qstate_iov(fd, &state->rcv, TCP_RECV_QUEUE)) {
        logerr("Error setting TCP_RECV_QUEUE iov");
        return -1;
    }
    if (set_tcp_qstate_iov(fd, &state->snd, TCP_SEND_QUEUE)) {
        logerr("Error setting TCP_SEND_QUEUE iov");
        return -1;
    }
    printf("Sent send queue\n");
            usleep(5e6);
    opt = 0;
    char buf[1024];
    if (read(fd, buf, 1024) < 0) {
        perror("Bad READ!");
    }
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt))) {
        perror("Unsetting TCP_REPAIR");
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

static int send_tcp_qstate(int fd, struct tcp_qstate *qstate) {
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

int send_tcp_state(int fd, struct tcp_state *state) {
    ssize_t sent;
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
    return 0;
}


static int recv_tcp_qstate(int fd, struct tcp_qstate *qstate) {
    ssize_t rcvd;
    if ((rcvd = recv(fd, &qstate->hdr, sizeof(qstate->hdr), 0)) != sizeof(qstate->hdr)) {
        perror("Error receiving qstate hdr");
        return -1;
    }

    qstate->msg_iov[0].iov_len = qstate->hdr.readlen;

    if ((rcvd = readv(fd, qstate->msg_iov, qstate->hdr.msg_iovlen)) < 0) {
        perror("Error readv'ing");
        return -1;
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
