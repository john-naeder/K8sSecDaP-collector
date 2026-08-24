# Native build — run on a node/host that has clang, bpftool, libbpf-dev and a
# BTF-enabled kernel. For the container build use ./build.sh instead.
#
#   make            # build build/tcp_connect.bpf.o + build/collector
#   make run        # sudo run the collector (emits JSON lines)
#   make image      # build the container image via build.sh
#   make clean

CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    ?= x86
BUILD   := build

SRC_KERN := src/kern/tcp_connect.bpf.c
SRC_USER := src/user/collector.cpp src/user/pod_meta.cpp

.PHONY: all run image clean test
all: $(BUILD)/tcp_connect.bpf.o $(BUILD)/collector

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/tcp_connect.bpf.o: $(SRC_KERN) $(BUILD)/vmlinux.h
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(BUILD) -c $(SRC_KERN) -o $@
	llvm-strip -g $@

$(BUILD)/collector: $(SRC_USER) src/user/pod_meta.h
	$(CLANG)++ -O2 -std=c++17 -Wall $(SRC_USER) -lbpf -lelf -lz -o $@

# Unit test for the offline /proc pod-metadata parsers. No kernel/libbpf needed.
$(BUILD)/test_pod_meta: src/user/pod_meta.cpp src/user/pod_meta.h tests/test_pod_meta.cpp | $(BUILD)
	$(CLANG)++ -O2 -std=c++17 -Wall -Isrc/user \
		src/user/pod_meta.cpp tests/test_pod_meta.cpp -o $@

test: $(BUILD)/test_pod_meta
	$(BUILD)/test_pod_meta

run: all
	cd $(BUILD) && sudo ./collector

image:
	./build.sh

clean:
	rm -rf $(BUILD) btf
