cmake_minimum_required(VERSION 3.16)
project(ebpf-collector LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ─── User-space collector ───────────────────────────────────────────────────
# Requires libbpf-dev and libbpf headers
find_library(LIBBPF bpf)
find_library(LIBELF elf)
find_library(LIBZ z)

if(LIBBPF AND LIBELF AND LIBZ)
    add_executable(collector src/user/collector.cpp)
    target_link_libraries(collector PRIVATE ${LIBBPF} ${LIBELF} ${LIBZ})
    message(STATUS "eBPF collector: will build (libbpf found)")
else()
    message(WARNING "eBPF collector: skipped (install libbpf-dev, libelf-dev, zlib1g-dev)")
endif()

# ─── Kernel BPF object ─────────────────────────────────────────────────────
# Build tcp_connect.bpf.o from .bpf.c using clang
# Requires: clang, kernel headers, bpftool (for vmlinux.h)
#
# Manual build steps:
#   1. Generate vmlinux.h:
#      bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#   2. Compile BPF object:
#      clang -O2 -g -target bpf \
#        -I. -I/usr/include/bpf \
#        -c src/kern/tcp_connect.bpf.c \
#        -o tcp_connect.bpf.o
