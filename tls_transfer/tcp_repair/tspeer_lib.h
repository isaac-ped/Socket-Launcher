#ifndef TSPEER_LIB_H_
#define TSPEER_LIB_H_
#include <arpa/inet.h>

struct tsock_server *init_tsock_server(struct sockaddr_in *ctl_addr,
                                       struct sockaddr_in *app_addr,
                                       struct sockaddr_in *proxy_addr, int self_id);

int start_tsock_server(struct tsock_server *server);
void stop_tsock_server(struct tsock_server *server);
void join_tsock_server(struct tsock_server *server);

int tsock_accept(struct tsock_server *server, int timeout_ms);
int tsock_transfer(struct tsock_server *server, int peer_id, int fd);

#endif
