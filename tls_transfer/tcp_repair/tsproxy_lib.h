#ifndef TSPROXY_LIB_H_
#define TSPROXY_LIB_H_
#include <arpa/inet.h>

int proxy_ctl_loop(struct sockaddr_in *ctl_addr);

#endif
