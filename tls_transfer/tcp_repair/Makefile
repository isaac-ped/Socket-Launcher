TARGETS=repair_sender repair_receiver
TARGETS+=tsproxy
OBJS=tcp_repair.o tsproxy_lib.o tspeer_lib.o communication.o
DEPS=tcp_repair.h
CFLAGS+=-Wall
LFLAGS+=-lpthread

all: ${TARGETS}

clean:
	rm ${TARGETS} ${OBJS}

%.o: %.c ${DEPS} Makefile
	gcc ${CFLAGS} -c $<

%: %.c

${TARGETS}: ${OBJS}
	gcc ${CFLAGS} $@.c $^ -o $@ ${LFLAGS}
