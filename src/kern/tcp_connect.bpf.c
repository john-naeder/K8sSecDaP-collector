// SPDX-License-Identifier: GPL-2.0
// Zero-Trust Network Mapper — eBPF Kernel Module
//
// Hooks tcp_v4_connect via kprobe to capture every outgoing TCP connection.
// Uses BPF_MAP_TYPE_LPM_TRIE for fast CIDR classification in kernel space.
// Emits network_event_t to user space via BPF_MAP_TYPE_RINGBUF.
//
// Build requires: libbpf, bpftool, kernel headers >= 5.8

#include "vmlinux.h"          // BTF-generated kernel types (bpftool btf dump)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Shared types (must match user-space common.h) ─────────────────────────

struct network_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u32 pid;
    __u64 timestamp_ns;
    // ── Runtime/K8s context (resolved to pod/namespace in user space) ──────
    __u64 cgroup_id;    // bpf_get_current_cgroup_id() — join key for container/pod
    __u32 ppid;         // parent TGID (process ancestry)
    __u32 uid;          // real UID of the connecting task
    char  comm[16];     // process name (e.g. "nmap", "curl", "bash")
};

// ─── LPM Trie key for CIDR matching ────────────────────────────────────────

struct lpm_key {
    __u32 prefixlen;    // Number of significant bits (e.g., 16 for /16)
    __u32 addr;         // IPv4 address in network byte order
};

// ─── BPF Maps ──────────────────────────────────────────────────────────────

// LPM Trie: CIDR prefix → label (1=pod, 2=svc, 3=node, 0=external)
// BPF_F_NO_PREALLOC is REQUIRED for LPM_TRIE maps.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cidr_map SEC(".maps");

// Ring Buffer for streaming events to user space.
// Size must be page-aligned (256KB = 262144 bytes).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Per-task storage to pass dst_addr between kprobe entry and return.
// We store the struct sock pointer on kprobe entry, read it on kretprobe.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);            // pid_tgid
    __type(value, struct sock *);
    __uint(max_entries, 4096);
} sock_store SEC(".maps");

// ─── Kprobe: tcp_v4_connect entry ──────────────────────────────────────────
// Signature: int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
// We save the sock pointer keyed by pid_tgid for the return probe.

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_entry, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&sock_store, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

// ─── Kretprobe: tcp_v4_connect return ──────────────────────────────────────
// Only emit event if connect() returned 0 (success) or -EINPROGRESS (async).

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_return, int ret)
{
    // Only proceed on success (0) or async in-progress (-EINPROGRESS = -115)
    if (ret != 0 && ret != -115)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Retrieve saved sock pointer
    struct sock **skp = bpf_map_lookup_elem(&sock_store, &pid_tgid);
    if (!skp)
        return 0;

    struct sock *sk = *skp;
    bpf_map_delete_elem(&sock_store, &pid_tgid);

    // Read connection details from sock
    __u32 dst_ip = 0;
    __u16 dst_port = 0;
    __u32 src_ip = 0;

    BPF_CORE_READ_INTO(&dst_ip, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&src_ip, sk, __sk_common.skc_rcv_saddr);

    // dst_port is in network byte order — convert to host order
    dst_port = __builtin_bswap16(dst_port);

    // ── Source filter: only emit Pod-sourced connections ───────────────────
    // Threat model = compromised Pod. Look up the SOURCE in cidr_map and drop
    // anything not labelled 1 (pod network). This removes node/host/external
    // false positives (e.g. the node's own outbound traffic) in kernel space,
    // and reduces events streamed to user space.
    struct lpm_key src_key = {
        .prefixlen = 32,
        .addr = src_ip,    // network byte order, same as map keys
    };
    __u32 *src_label = bpf_map_lookup_elem(&cidr_map, &src_key);
    if (!src_label || *src_label != 1)
        return 0;

    // Optional: LPM Trie lookup to classify destination
    // Label 0 = unknown/external (still emit — user space handles classification too)
    struct lpm_key lookup_key = {
        .prefixlen = 32,
        .addr = dst_ip,    // already in network byte order from kernel
    };
    __u32 *label = bpf_map_lookup_elem(&cidr_map, &lookup_key);
    // label can be used for kernel-side filtering if needed
    // For now, we emit ALL events and let user space classify

    // Reserve space in ring buffer
    struct network_event_t *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    // Fill event — IPs stored in network byte order for consistency
    evt->src_ip = src_ip;
    evt->dst_ip = dst_ip;
    evt->dst_port = dst_port;
    evt->pid = pid_tgid >> 32;    // Upper 32 bits = TGID (process ID)
    evt->timestamp_ns = bpf_ktime_get_ns();

    // ── Runtime/K8s context ────────────────────────────────────────────────
    evt->cgroup_id = bpf_get_current_cgroup_id();
    evt->uid       = (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // Parent TGID via current task → real_parent → tgid (CO-RE).
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Submit to ring buffer
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

// License is required for BPF programs using kernel helpers
char LICENSE[] SEC("license") = "GPL";
