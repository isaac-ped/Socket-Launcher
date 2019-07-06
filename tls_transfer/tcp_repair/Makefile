CC?=gcc
CFLAGS+=-Wall -g
LFLAGS+=-lpthread -lzmq

TARGETS=repair_sender repair_receiver
TARGETS+=tspeer
OBJS=tcp_repair.o tsproxy_lib.o tspeer_lib.o communication.o file-db-pool.o
DEPS=tcp_repair.h communication.h

XDP_TARGETS=tsproxy_xdp
XDP_OBJS=tcp_repair.o tsproxy_xdp_lib.o communication.o

all: ${TARGETS} ${XDP_TARGETS}

clean:
	rm -f ${TARGETS} ${OBJS}

%.o: %.c ${DEPS} Makefile
	$(CC) ${CFLAGS} -c $<

${TARGETS}: ${OBJS}

${XDP_TARGETS}: tsproxy.c ${XDP_OBJS}
	$(CC) ${CFLAGS} $< ${XDP_OBJS} -o $@ ${LFLAGS}

% :: %.c
	$(CC) ${CFLAGS} $< ${OBJS} -o $@ ${LFLAGS}

.PHONY: all
