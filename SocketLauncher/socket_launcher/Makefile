CC?=gcc
CFLAGS+=-Wall -g -O3 --std=gnu99 -fPIC
LFLAGS+=-lpthread -lzmq -lm

TARGETS+=tspeer echo_server eb_echo_server eb_tspeer eb_notspeer eb_post_tspeer eb_q_tspeer
OBJS=tcp_repair.o tspeer_lib.o communication.o file-db-pool.o
DEPS=tcp_repair.h communication.h logging.h

XDP_TARGETS=tsproxy_xdp
XDP_OBJS=tcp_repair.o tsproxy_xdp_lib.o communication.o

all: ${TARGETS} ${XDP_TARGETS} ${BPF_OBJS}

clean:
	rm -f ${TARGETS} ${OBJS}

%.o: %.c ${DEPS} Makefile
	$(CC) ${CFLAGS} -c $<

${TARGETS}: ${OBJS}

${XDP_TARGETS}: tsproxy.c ${XDP_OBJS}
	$(CC) ${CFLAGS} $< ${XDP_OBJS} -o $@ ${LFLAGS}

% :: %.c
	$(CC) ${CFLAGS} $< ${OBJS} -o $@ ${LFLAGS}

dosu: all
	chown root:iped ${TARGETS}
	chmod gu+sx ${TARGETS}

.PHONY: all
