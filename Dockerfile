# syntax=docker/dockerfile:1
#
# K8sSecDaP eBPF collector — multi-stage build.
#
#   builder: generate vmlinux.h from a kernel BTF blob (staged into the build
#            context as ./btf/vmlinux by build.sh or CI), compile the CO-RE
#            eBPF object, then build the user-space libbpf collector.
#   runtime: minimal Debian + libbpf runtime + the two artifacts.
#
# vmlinux.h is CO-RE portable: the build machine's BTF only supplies type
# definitions for compilation; field offsets are relocated at load time against
# the TARGET node's /sys/kernel/btf/vmlinux. So building on a newer kernel than
# the cluster nodes is fine as long as the referenced types exist on the target.
#
# Build:  ./build.sh         (stages BTF, then `docker build`)
# Assumes x86_64 nodes (override ARCH for arm64).

ARG ARCH=x86

# ──────────────────────────── builder ──────────────────────────────────────
FROM debian:bookworm-slim AS builder
ARG ARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
# Raw kernel BTF blob, staged into the context by build.sh / CI (NOT committed).
COPY btf/vmlinux /work/btf/vmlinux
COPY src/ /work/src/

# 1) vmlinux.h from the staged BTF (kept out of the source tree).
RUN mkdir -p /work/include \
 && bpftool btf dump file /work/btf/vmlinux format c > /work/include/vmlinux.h

# 2) Compile the CO-RE eBPF object.
RUN clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_${ARCH} \
        -I/work/include \
        -c /work/src/kern/tcp_connect.bpf.c \
        -o /work/tcp_connect.bpf.o \
 && llvm-strip -g /work/tcp_connect.bpf.o

# 3) Build the user-space collector (libbpf + libelf + zlib).
RUN clang++ -O2 -std=c++17 -Wall \
        /work/src/user/collector.cpp \
        -lbpf -lelf -lz \
        -o /work/collector

# ──────────────────────────── runtime ──────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libbpf1 libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# collector loads ./tcp_connect.bpf.o relative to its CWD.
COPY --from=builder /work/collector          /app/collector
COPY --from=builder /work/tcp_connect.bpf.o  /app/tcp_connect.bpf.o

# Emits one JSON line per TCP connect on stdout. Needs CAP_BPF/CAP_PERFMON +
# host BTF mounted (see the DaemonSet manifest).
ENTRYPOINT ["/app/collector"]
