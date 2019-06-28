#include "communication.h"

#include <stdio.h>

int send_tsock_msg(int fd, enum msg_type type, void *payload, size_t payload_size) {
    struct tsock_hdr hdr = {type};
    if (send(fd, &hdr, sizeof(hdr), 0) != sizeof(hdr)) {
        perror("Sending hdr");
        return -1;
    }
    if (send(fd, payload, payload_size, 0) != payload_size) {
        perror("Sending payload");
        return -1;
    }
    return 0;
}


int create_listening_fd(struct sockaddr_in *addr) {

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
