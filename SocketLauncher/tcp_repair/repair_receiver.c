#include "logging.h"
#include "tcp_repair.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>

#define READLEN 1024

void *socket_handler(void *vfd) {
    int fd = (intptr_t)vfd;

    while (1) {
        char buf[READLEN];
        ssize_t readlen = read(fd, buf, READLEN);
        if (readlen < 0) {
            perror("reading from fd");
            close(fd);
            return NULL;
        }
        buf[readlen] = '\0';
        printf("Read: %s\n", buf);
        ssize_t writeln = write(fd, buf, readlen);
        (void)writeln;
    }
    close(fd);

    return NULL;
}
#define N_THREADS 32

int main(int argc, char **argv) {
    if (argc < 3) {
        logerr("Usage: %s IP PORT", argv[0]);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("Socket");
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(atoi(argv[2]))
    };

    if (inet_aton(argv[1], &addr.sin_addr) == 0) {
        perror("inet_aton");
        return -1;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr))) {
        perror("connect");
        return -1;
    }

    printf("Connected\n");

    pthread_t threads[N_THREADS];
    int uses[N_THREADS];
    memset(uses, 0, sizeof(uses));

    while (1) {
        for (int i=0; i < N_THREADS; ++i) {
            if (uses[i]) {
                pthread_join(threads[i], NULL);
            }
            struct tcp_state state;
            init_tcp_state(&state);
            if (recv_tcp_state(fd, &state)) {
                logerr("Error recving tcp state");
                return -1;
            }
            print_tcp_state(&state);

            int new_fd = socket(AF_INET, SOCK_STREAM, 0);

            if (set_tcp_state(new_fd, &state, &addr.sin_addr)) {
                logerr("Error setting tcp state");
                return -1;
            }
            usleep(5e6);
            int rtn = pthread_create(&threads[i], NULL, socket_handler,
                                     (void*)(intptr_t)new_fd);
            if (rtn < 0) {
                perror("Error creating thread");
                return -1;
            }
            uses[i]++;
        }
    }

    return 0;
}
