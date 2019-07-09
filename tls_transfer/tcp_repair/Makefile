CC?=gcc
CFLAGS+=-Wall -g
LFLAGS+=-lpthread -lzmq

TARGETS=repair_sender repair_receiver
TARGETS+=tspeer
OBJS=tcp_repair.o tspeer_lib.o communication.o file-db-pool.o
DEPS=tcp_repair.h communication.h logging.h

XDP_TARGETS=tsproxy_xdp
XDP_OBJS=tcp_repair.o tsproxy_xdp_lib.o communication.o

BPF_OBJS=proxy_ebpf.o

all: ${TARGETS} ${XDP_TARGETS} ${BPF_OBJS}

clean:
	rm -f ${TARGETS} ${OBJS}

%_ebpf.o: %_ebpf.c
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) -I$(obj) \
		-I$(srctree)/tools/testing/selftests/bpf/ \
		-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
		-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@

%.o: %.c ${DEPS} Makefile
	$(CC) ${CFLAGS} -c $<

${TARGETS}: ${OBJS}

${XDP_TARGETS}: tsproxy.c ${XDP_OBJS}
	$(CC) ${CFLAGS} $< ${XDP_OBJS} -o $@ ${LFLAGS}

% :: %.c
	$(CC) ${CFLAGS} $< ${OBJS} -o $@ ${LFLAGS}

.PHONY: all
