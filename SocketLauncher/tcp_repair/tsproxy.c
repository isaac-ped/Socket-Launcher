#include "logging.h"
#include "tsproxy_lib.h"

#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        logerr("Usage: %s CTL_IP CTL_PORT", argv[0]);
        return -1;
    }
    int ctl_port = atoi(argv[2]);

    struct sockaddr_in ctl_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(ctl_port),
    };

    if (inet_pton(AF_INET, argv[1], &ctl_addr.sin_addr) != 1) {
        perror("inet_pton");
        return -1;
    }

    loginfo("Entering proxy ctl loop");
    return proxy_ctl_loop(&ctl_addr);
}
