#include "tcp_repair.h"
#include "logging.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#define N_BEFORE_XFER 2
#define READLEN 1024

static int ctl_fd;

void *socket_handler(void *vfd) {
    int fd = (intptr_t)vfd;

    char buf[READLEN];
    for (int i=0; i < N_BEFORE_XFER; i++) {
        ssize_t readlen = read(fd, buf, READLEN);
        if (readlen < 0) {
            perror("reading from fd");
            return NULL;
        }
        buf[readlen] = '\0';
        printf("Read: %s\n", buf);
        write(fd, buf, readlen+1);
    }
    usleep(2e6);
    read(fd, buf, 0);
    printf("Getting tcp state\n");

    struct tcp_state state;
    init_tcp_state(&state);
    get_tcp_state(fd, &state);
    print_tcp_state(&state);
    send_tcp_state(ctl_fd, &state);

    return NULL;
}

static int create_listening_fd(int port) {

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("Socket");
        return -1;
    }
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("REUSEADDR");
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return -1;
    }

    if (listen(fd, 1024)) {
        perror("listen");
        return -1;
    }
    return fd;
}

#define N_THREADS 32

int main(int argc, char **argv) {
    if (argc < 3) {
        logerr("Usage: %s PORT CTL_PORT", argv[0]);
        return -1;
    }

    int fd = create_listening_fd(atoi(argv[1]));
    int ctl_listen_fd = create_listening_fd(atoi(argv[2]));

    ctl_fd = accept(ctl_listen_fd, NULL, NULL);

    pthread_t threads[N_THREADS];
    int uses[N_THREADS];
    memset(uses, 0, sizeof(uses));

    while (1) {
        for (int i=0; i < N_THREADS; i++) {
            if (uses[i]) {
                pthread_join(threads[i], NULL);
            }
            int newfd = accept(fd, NULL, NULL);
            int rtn = pthread_create(&threads[i], NULL, socket_handler, (void*)(intptr_t)newfd);
            if (rtn < 0) {
                perror("Error creating thread");
                return -1;
            }
            uses[i]++;
        }
    }
    return 0;
}
