#include "logging.h"
#include "tspeer_lib.h"
#include "file-db-pool.h"

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>

#define SHOW_USAGE(err) printf(err "\nUsage: %s APP_PORT IP\n", argv[0]);

static int epollfd;

void read_loop(void *vfd, void *unused) {
    int fd = (intptr_t)vfd;
    loginfo("Activity on fd %d", fd);
    char buf[1024];
    ssize_t recvd = recv(fd, buf, 1024, 0);
    loginfo("Received on fd %d: %s\n", fd, buf);
    if (recvd < 0) {
        perror("Recv from client");
        if(epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL)) {
            perror("epoll_ctl");
        }
        close(fd);
        return;
    }
    if (recvd == 0) {
        loginfo("Client disconnect");
        if(epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL)) {
            perror("epoll_ctl");
        }
        close(fd);
        return;
    }
    buf[recvd] = '\0';
    loginfo("Received on fd %d: %s\n", fd, buf);
    send(fd, buf, recvd, 0);
    //send(fd, buf, recvd, 0);
    loginfo("Sent on fd %d: %s\n", fd, buf);
}

#define N_THREADS 32
#define MAX_EVENTS 64

int main(int argc, char **argv) {
    if (argc != 3) {
        SHOW_USAGE("Not enough args");
        return -1;
    }
    int app_port = atoi(argv[1]);

    char *local_ip = argv[2];

    struct sockaddr_in app_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(app_port)
    };
    if (inet_pton(AF_INET, local_ip, &app_addr.sin_addr) != 1) {
        perror("inet_pton");
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (bind(sock, (struct sockaddr*)&app_addr, sizeof(app_addr)) == -1) {
        perror("bind");
        return -1;
    }

    if (listen(sock, 1024) == -1) {
        perror("listen");
        return -1;
    }

    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1");
        return -1;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = sock;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev) == -1) {
        perror("epol_ctl");
        return -1;
    }

    struct thread_pool *tp = init_thread_pool(50, read_loop, NULL, -1);

    while (1) {

        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            logerr("Error accept");
            break;
        }

        for (int n=0; n < nfds; ++n) {
            if (events[n].data.fd == sock) {
                int newfd = accept(sock, NULL, NULL);
                if (newfd == -1) {
                    perror("Accept");
                    exit(-1);
                }
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = newfd;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, newfd, &ev) == -1) {
                    perror("epoll_ctl");
                    return -1;
                }
            } else {
                if (ev.events & EPOLLIN) {
                    tp_enqueue(tp, (void*)(intptr_t)events[n].data.fd);
                } else {
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, events[n].data.fd, NULL);
                    close(events[n].data.fd);
                }
            }
        }
    }
}
