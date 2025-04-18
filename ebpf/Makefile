LLC ?= llc
CLANG ?= clang
CC = gcc

BPF_CFLAGS ?= -I/usr/include/bpf/
CFLAGS = -g -Wall -Wpedantic -std=c17 -I/usr/include/bpf/
LDLIBS = -lbpf
LDFLAGS = -L/usr/lib64

.PHONY: all clean

test: rocksdb_parser.h ebpf.h

test_bpfof: rocksdb_parser.h ebpf.h

parser.o: parser.c rocksdb_parser.h data_block_footer.h ebpf.h
	$(CLANG) -S -g\
		-target bpf \
		-D __BPF_TRACING__ \
		-DROCKSDB_EBPF \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

read.o: read.c ebpf.h
	$(CLANG) -S -g\
		-target bpf \
		-D __BPF_TRACING__ \
		-DROCKSDB_EBPF \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

all: test test_bpfof parser.o

clean:
	rm -f -- *.o *.ll test
