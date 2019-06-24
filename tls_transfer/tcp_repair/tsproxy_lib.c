#include "logging.h"
#include "communication.h"
#include "tsock.h"

#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>

#define CONNTRACK_PATH "/usr/sbin/conntrack"

static int get_ip_and_port(struct sockaddr_in *addr, char ip[16], char port[8]) {
    if (inet_ntop(AF_INET, addr, ip, sizeof(*addr)) == NULL) {
        perror("inet_ntop");
        return -1;
    }
    snprintf(port, 8, "%d", ntohs(addr->sin_port));
    return 0;
}

static char *flush_cmd[] = {
    "iptables", "-t", "nat", "-F"
};

static int run_flush_cmd(void) {
    pid_t pid = fork();
    if (pid == 0) {
        execv(CONNTRACK_PATH, flush_cmd);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }
    return 0;
}

static char* dnat_cmd[] = {
    "iptables", "-A", "PREROUTING", "-t", "nat", "-p", "tcp", "-j", "DNAT", "-m", "statistic",
    "--node", "nth", "--packet", "0", "--dport", NULL, "-d", NULL, "--to-destination", NULL,
    "--every", NULL, NULL 
};

static int run_dnat_cmd(char *app_port, char *proxy_ip, char *server_ip, char *n) {
    pid_t pid = fork();
    if (pid == 0) {
        dnat_cmd[16] = app_port;
        dnat_cmd[18] = proxy_ip;
        char server_addr[32];
        snprintf(server_addr, 32, "%s:%s", server_ip, app_port);
        dnat_cmd[20] = server_addr;
        dnat_cmd[22] = n;
        execv(CONNTRACK_PATH, dnat_cmd);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }
    return 0;
}

static char *snat_cmd[] = {
    "iptables", "-A", "POSTROUTING", "-t", "nat", "-p", "tcp", "-j", "SNAT", "-d", NULL,
    "--dport", NULL, "--to_source", NULL, NULL
};

static int run_snat_cmd(char *server_ip, char *app_port, char *proxy_ip) {
    pid_t pid = fork();
    if (pid == 0) {
        snat_cmd[10] = server_ip;
        snat_cmd[12] = app_port;
        snat_cmd[14] = proxy_ip;
        execv(CONNTRACK_PATH, snat_cmd);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }

    return 0;
}

static char* del_cmd[] = {
    "conntrack", "-D", "-s",  NULL, "-p", "TCP", "--sport", NULL, NULL
};

static int run_del_cmd(char *sip, char *sport) {
    pid_t pid = fork();
    if (pid == 0) {
        del_cmd[3] = sip;
        del_cmd[7] = sport;
        execv(CONNTRACK_PATH, del_cmd);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }
    return 0;
}

static char* ins_cmd[] = {
    "conntrack", "-I", "-p", "TCP", "-t", "1000", "--src", NULL,
    "--dst", NULL, "--sport", NULL, "--dport", NULL, "--src-nat", NULL,
    "--dst-nat", NULL, "--state", "NONE", NULL
};

static int run_insert_cmd(char *dst, char *self, char *dport, char *sport, char *sip) {
    pid_t pid = fork();
    if (pid == 0) {
        ins_cmd[7] = dst;
        ins_cmd[9] = self;
        ins_cmd[11] = dport;
        ins_cmd[13] = sport;
        ins_cmd[15] = self;
        ins_cmd[17] = sip;
        execv(CONNTRACK_PATH, ins_cmd);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }
    return 0;
}

static const char* list_cmd_template = "conntrack -L --reply-src %s -p TCP --sport %s";
#define MAX_LIST_CMDLEN (strlen(list_cmd_template) + 24)
#define MAX_LIST_OUTLEN 2048
static int get_sip(char *orig_ip, char *sport, char sip[16]) {
    char cmd[MAX_LIST_CMDLEN];
    snprintf(cmd, MAX_LIST_CMDLEN, list_cmd_template, orig_ip, sport);

    FILE *fp;
    if ((fp = popen(cmd, "r")) == NULL) {
        perror("Error opening pipe");
        return -1;
    }

    char buf[MAX_LIST_OUTLEN];
    while (fgets(buf, MAX_LIST_OUTLEN, fp) != NULL) {
        char *srcstart = strstr(buf, "src=");
        if (srcstart != NULL) {
            char *srcend = strstr(srcstart, " ");
            strncpy(sip, srcstart, (srcend - srcstart));
            sip[srcend - srcstart] = '\0';
            return 0;
        }
    }
    logerr("Could not find sip in output");
    return -1;
}


struct peer_info {
    int fd;
    struct sockaddr_in app_addr;
};

struct peer_loop_arg {
    struct peer_info *peers;
    char *self_ip;
    int peer_id;
};

static int reset_nat(struct peer_info peers[MAX_PEERS], char *self_ip) {
    int n_peers = 0;
    for (int i=0; i < MAX_PEERS; i++) {
        if (peers[i].fd)
            ++n_peers;
    }
    run_flush_cmd();
    for (int i=0; i < MAX_PEERS; i++) {
        if (peers[i].fd) {
            char peer_ip[16], peer_port[8];
            if (get_ip_and_port(&peers[i].app_addr, peer_ip, peer_port)) {
                return -1;
            }
            char peer_n[3];
            snprintf(peer_n, 3, "%d", n_peers);
            if (run_dnat_cmd(peer_port, self_ip, peer_ip, peer_n)) {
                return -1;
            }
            if (run_snat_cmd(peer_ip, peer_port, self_ip)) {
                return -1;
            }
            --n_peers;
        }
    }
    return 0;
}



static int handle_redirect(struct peer_info *peers, struct redirect_msg *msg, char *self_ip) {
    struct sockaddr_in *orig_addr = &peers[msg->orig_peer].app_addr;
    struct sockaddr_in *next_addr = &peers[msg->next_peer].app_addr;

    char orig_ip[16], orig_port[8];
    if (get_ip_and_port(orig_addr, orig_ip, orig_port)) {
        return -1;
    }
    char next_ip[16], next_port[8];
    if (get_ip_and_port(next_addr, next_ip, next_port)) {
        return -1;
    }
    char sport[8];
    snprintf(sport, 8, "%d", ntohs(msg->n_sport));
    char sip[16];
    if (get_sip(orig_ip, sport, sip)) {
        return -1;
    }

    if (run_del_cmd(sip, sport)) {
        return -1;
    }
    if (run_insert_cmd(next_ip, self_ip, next_port, sport, sip)) {
        return -1;
    }
    return 0;
}


static void *peer_loop(void *varg) {
    struct peer_loop_arg *arg = varg;
    int fd = arg->peers[arg->peer_id].fd;

    struct tsock_hdr hdr;
    struct redirect_msg msg;
    ssize_t recvd;
    int err = 0;
    while (err == 0) {
        recvd = recv(fd, &hdr, sizeof(hdr), 0);
        if (recvd != sizeof(hdr)) {
            perror("Recv from peer");
            break;
        }
        switch(hdr.type) {
            case REDIRECT:
                recvd = recv(fd, &msg, sizeof(&msg), 0);
                if (recvd != sizeof(msg)) {
                    perror("Recv msg from peer");
                    err = 1;
                    break;
                }
                if (handle_redirect(arg->peers, &msg, arg->self_ip)) {
                    logerr("Error handing redirect");
                    err = 1;
                    break;
                }
                break;
            default:
                logerr("Received unknown msg type %d", hdr.type);
                err = 1;
                break;
        }
    }
    close(fd);
    arg->peers[arg->peer_id].fd = 0;
    free(arg);
    return NULL;
}

int proxy_ctl_loop(struct sockaddr_in *ctl_addr) {
    int ctl_fd = create_listening_fd(ctl_addr);
    char self_ip[16], self_port[8];
    if (get_ip_and_port(ctl_addr, self_ip, self_port)) {
        return -1;
    }

    pthread_t peer_threads[MAX_PEERS] = {};
    struct peer_info peers[MAX_PEERS] = {};

    while (1) {
        int newfd = accept(ctl_fd, NULL, NULL);
        struct tsock_hdr hdr;
        if (recv(newfd, &hdr, sizeof(hdr), 0) != sizeof(hdr)) {
            perror("recv from newfd");
            break;
        }
        if (hdr.type != HELLO) {
            logerr("Received non-hello type message %d", hdr.type);
            break;
        }
        struct hello_msg msg;
        if (recv(newfd, &msg, sizeof(msg), 0) != sizeof(msg)) {
            perror("Recv from newfd");
            break;
        }

        if (peers[msg.peer_id].fd) {
            logerr("Peer %d already joined", msg.peer_id);
            break;
        }

        for (int i=0; i < MAX_PEERS; ++i) {
            if (peers[msg.peer_id].fd) {
                if (send_tsock_msg(peers[msg.peer_id].fd, PEER_JOIN, &msg, sizeof(msg))) {
                    logerr("Forwarding PEER_JOIN");
                    return -1;
                }
            }
        }

        peers[msg.peer_id].fd = newfd;
        peers[msg.peer_id].app_addr = msg.app_addr;

        struct peer_loop_arg *arg = malloc(sizeof(*arg));
        arg->peers = peers;
        arg->peer_id = msg.peer_id;
        arg->self_ip = self_ip;
        if (peer_threads[msg.peer_id]) {
            loginfo("Waiting for existing thread to join");
            pthread_join(peer_threads[msg.peer_id], NULL);
        }
        reset_nat(peers, self_ip);

        int rtn = pthread_create(&peer_threads[msg.peer_id], NULL, peer_loop, arg);
        if (rtn) {
            perror("Pthread_create");
            return -1;
        }
    }
    return 0;
}


