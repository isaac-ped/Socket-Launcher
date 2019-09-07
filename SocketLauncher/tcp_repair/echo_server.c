#include "logging.h"
#include "tspeer_lib.h"
#include "file-db-pool.h"

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pthread.h>
#include <netinet/tcp.h>

#define SHOW_USAGE(err) printf(err "\nUsage: %s APP_PORT IP\n", argv[0]);


void read_loop(void *vfd, void *unused) {
    int fd = (intptr_t)vfd;
    loginfo("Got new fd %d", fd);

    char buf[1024];
    for (int i=0; i < 10000; i++) {
        ssize_t recvd = recv(fd, buf, 1024, 0);
        loginfo("Received on fd %d: %s\n", fd, buf);
        if (recvd < 0) {
            perror("Recv from client");
            close(fd);
            return;
        }
        if (recvd == 0) {
            loginfo("Client disconnect");
            close(fd);
            return;
        }
        buf[recvd] = '\0';
        loginfo("Received on fd %d: %s\n", fd, buf);
        send(fd, buf, recvd, 0);
        //send(fd, buf, recvd, 0);
        loginfo("Sent on fd %d: %s\n", fd, buf);
        recvd = recv(fd, buf, 1024, MSG_PEEK);
        loginfo("Received next msg: %s\n", buf);
    }
    return;
}

#define N_THREADS 32

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

    struct thread_pool *tp = init_thread_pool(50, read_loop, NULL, -1);

    while (1) {
        int new_fd = accept(sock, NULL, NULL);
        if (new_fd < 0) {
            logerr("Error accepting");
            break;
        }
        if (new_fd == 0) {
            continue;
        }

        tp_enqueue(tp, (void*)(intptr_t)new_fd);
    }
}
