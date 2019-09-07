#include "logging.h"
#include "tspeer_lib.h"
#include "file-db-pool.h"
#include "tsock.h"

#include <sys/epoll.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pthread.h>
#include <netinet/tcp.h>

#define SHOW_USAGE(err) logerr(err "\nUsage: %s APP_PORT PROXY_IP:PORT CTL_IP:PORT ID XFER_COUNT", argv[0]);

static struct tsock_server *tss;
static int local_id;
static int xfer_count = 0;
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
    int newid = (local_id + 1) % 2;
    if (strcmp(buf, "xfer") == 0) {
        tsock_transfer(tss, newid, fd);
    }
}

#define N_THREADS 32
#define MAX_EVENTS 64

int main(int argc, char **argv) {
    if (argc != 6) {
        SHOW_USAGE("Not enough args");
        return -1;
    }
    xfer_count = atoi(argv[5]);
    local_id = atoi(argv[4]);
    int app_port = atoi(argv[1]);

    char *local_ip = strtok(argv[3], ":");
    char *ctl_port_s = strtok(NULL, "");
    if (ctl_port_s == NULL) {
        SHOW_USAGE("Bad ctl addr");
        return -1;
    }
    int ctl_port = atoi(ctl_port_s);

    char *proxy_ip = strtok(argv[2], ":");
    char *proxy_port_s = strtok(NULL, "");
    if (proxy_port_s == NULL) {
        SHOW_USAGE("Bad proxy addr");
        return -1;
    }

    int proxy_port = atoi(proxy_port_s);

    struct sockaddr_in ctl_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(ctl_port)
    };
    if (inet_pton(AF_INET, local_ip, &ctl_addr.sin_addr) != 1) {
        perror("inet_pton");
        return -1;
    }
    struct sockaddr_in app_addr = ctl_addr;
    app_addr.sin_port = htons(app_port);

    struct sockaddr_in proxy_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(proxy_port)
    };

    if (inet_pton(AF_INET, proxy_ip, &proxy_addr.sin_addr) != 1) {
        perror("inet_pton for proxy");
        return -1;
    }

    struct tsock_server *server = init_tsock_server(&ctl_addr, &app_addr, &proxy_addr, atoi(argv[4]));
    tss = server;
    if (!server) {
        logerr("Error intializing server");
        return -1;
    }
    if (start_tsock_server(server)) {
        return -1;
    }

    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1");
        return -1;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = server->app_fd;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, server->app_fd, &ev) == -1) {
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
            if (events[n].data.fd == server->app_fd) {
                int newfd = accept(server->app_fd, NULL, NULL);
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
    stop_tsock_server(server);
    join_tsock_server(server);
}
