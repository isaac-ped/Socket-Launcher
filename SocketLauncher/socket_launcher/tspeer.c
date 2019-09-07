#include "logging.h"
#include "tspeer_lib.h"
#include "file-db-pool.h"

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

void read_loop(void *vfd, void *unused) {
    int fd = (intptr_t)vfd;
    loginfo("Got new fd %d", fd);

    char buf[1024];
    ssize_t recvd = recv(fd, buf, 1024, 0);
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

    if (strcmp(buf, "transfer") == 0) {
        int newid = (local_id + 1) % 2;
        tsock_transfer(tss, newid, fd);
    }
    return;
}

#define N_THREADS 32

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

    struct thread_pool *tp = init_thread_pool(50, read_loop, NULL, -1);

    while (1) {
        int new_fd = tsock_accept(server, 500);
        if (new_fd < 0) {
            logerr("Error accepting");
            break;
        }
        if (new_fd == 0) {
            continue;
        }

        tp_enqueue(tp, (void*)(intptr_t)new_fd);

    }
    stop_tsock_server(server);
    join_tsock_server(server);
}
