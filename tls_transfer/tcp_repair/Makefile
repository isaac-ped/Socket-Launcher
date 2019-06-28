CC?=gcc
CFLAGS+=-Wall
LFLAGS+=-lpthread

TARGETS=repair_sender repair_receiver
TARGETS+=tsproxy tspeer
OBJS=tcp_repair.o tsproxy_lib.o tspeer_lib.o communication.o
DEPS=tcp_repair.h

all: ${TARGETS}

clean:
	rm -f ${TARGETS} ${OBJS}

%.o: %.c ${DEPS} Makefile
	$(CC) ${CFLAGS} -c $<

${TARGETS}: ${OBJS}

% :: %.c
	$(CC) ${CFLAGS} $< ${OBJS} -o $@ ${LFLAGS}

.PHONY: all
