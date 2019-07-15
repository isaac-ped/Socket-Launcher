#include "communication.h"
#include "logging.h"

#include <stdio.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int send_tsock_msg(int fd, enum msg_type type, void *payload, size_t payload_size,
                   pthread_mutex_t *mutex) {

    struct tsock_hdr hdr = {type};
    struct iovec vec[] = {
        {
            .iov_base = &hdr,
            .iov_len = sizeof(hdr)
        }, {
            .iov_base = payload,
            .iov_len = payload_size
        }
    };
    struct msghdr msg = {
        .msg_iov = vec,
        .msg_iovlen = 2
    };

    if (mutex) {
        loginfo("Locking mutex for %d", type);
        if (pthread_mutex_lock(mutex)) {
            perror("mutex lock");
        }
    }
    if (sendmsg(fd, &msg, 0) != payload_size + sizeof(hdr)) {
        perror("Sending message");
        return -1;
    }
    if (mutex) {
        loginfo("Unlocking mutex for %d", type);
        if (pthread_mutex_unlock(mutex)) {
            perror("mutex unlock");
        }
    }
    return 0;
}


int create_listening_fd(struct sockaddr_in *addr, bool quickack) {

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("Socket");
        return -1;
    }
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("REUSEADDR");
        return -1;
    }
    if (quickack) {
        opt = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt))) {
            perror("TCP_NODELAY");
            return -1;
        }
        opt = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt))) {
            perror("QUICKACK");
            return -1;
        }
    }

    if (bind(fd, (struct sockaddr*)addr, sizeof(*addr)) < 0) {
        perror("binding listen");
        return -1;
    }

    if (listen(fd, 1024)) {
        perror("listen");
        return -1;
    }
    return fd;
}
