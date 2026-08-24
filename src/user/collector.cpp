// Zero-Trust Network Mapper — User-Space eBPF Collector
//
// Loads tcp_connect.bpf.o, attaches kprobe/kretprobe,
// consumes events from ring buffer, and outputs JSON lines to stdout.
//
// Build: requires libbpf-dev, bpftool (for vmlinux.h generation)
// Run:   sudo ./collector [--json | --binary]
//
// Output format (JSON lines, one per event):
//   {"src_ip":"10.244.1.5","dst_ip":"10.244.2.3","dst_port":8080,"pid":12345,"timestamp_ns":1234567890}

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstdint>
#include <cerrno>
#include <string>
#include <unordered_map>

#include "pod_meta.h"

// Must match the struct in tcp_connect.bpf.c
struct network_event_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint32_t pid;
    uint64_t timestamp_ns;
    // Runtime/K8s context (resolved to pod/namespace below)
    uint64_t cgroup_id;
    uint32_t ppid;
    uint32_t uid;
    char     comm[16];
};

// cgroup_id → resolved pod metadata. Keyed by cgroup_id because it is stable
// per-container and survives the race where the connecting process exits
// before we read its /proc entries.
static std::unordered_map<uint64_t, ztmeta::PodMeta> g_meta_cache;

// Minimal JSON string escaper for comm/pod/namespace values.
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
    (void)sig;
    exiting = true;
}

// Convert network-byte-order IPv4 to dotted-decimal string
static void ip_to_str(uint32_t ip_nbo, char *buf, size_t len) {
    struct in_addr addr;
    addr.s_addr = ip_nbo;
    inet_ntop(AF_INET, &addr, buf, len);
}

// Ring buffer callback — invoked for each event
static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(network_event_t))
        return 0;

    const auto *evt = static_cast<const network_event_t *>(data);

    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    ip_to_str(evt->src_ip, src_str, sizeof(src_str));
    ip_to_str(evt->dst_ip, dst_str, sizeof(dst_str));

    // comm is a fixed 16-byte field, may not be NUL-terminated.
    char comm_buf[17];
    memcpy(comm_buf, evt->comm, sizeof(evt->comm));
    comm_buf[16] = '\0';

    // ── Resolve pod/namespace from cgroup_id (cached) ──────────────────────
    // Cache miss, or a previous miss that resolved nothing (pod may have been
    // gone): (re)resolve from the current pid's /proc entries.
    auto it = g_meta_cache.find(evt->cgroup_id);
    if (it == g_meta_cache.end() || it->second.container_id.empty()) {
        ztmeta::PodMeta m = ztmeta::resolve_pod_meta(evt->pid);
        it = g_meta_cache.insert_or_assign(evt->cgroup_id, std::move(m)).first;
    }
    const ztmeta::PodMeta& meta = it->second;

    // Output as JSON line (compatible with pipeline's file input — original
    // keys unchanged, new keys appended).
    printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"dst_port\":%u,"
           "\"pid\":%u,\"timestamp_ns\":%lu,"
           "\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\","
           "\"cgroup_id\":%lu,"
           "\"pod_name\":\"%s\",\"namespace\":\"%s\",\"container_id\":\"%s\"}\n",
           src_str, dst_str, evt->dst_port,
           evt->pid, evt->timestamp_ns,
           evt->ppid, evt->uid, json_escape(comm_buf).c_str(),
           evt->cgroup_id,
           json_escape(meta.pod_name).c_str(),
           json_escape(meta.namespace_).c_str(),
           json_escape(meta.container_id).c_str());
    fflush(stdout);

    return 0;
}

// Populate LPM Trie with K8s CIDR ranges
static int populate_cidr_map(int map_fd) {
    // Key format: { prefixlen, addr_in_network_byte_order }
    struct lpm_key {
        uint32_t prefixlen;
        uint32_t addr;
    };

    struct { struct lpm_key key; uint32_t label; const char *desc; } entries[] = {
        // Pod network: 10.244.0.0/16 → label 1
        { {16, htonl(0x0AF40000)}, 1, "pod_network" },
        // Service network: 10.96.0.0/12 → label 2
        { {12, htonl(0x0A600000)}, 2, "service_network" },
        // Node network: 192.168.0.0/16 → label 3
        { {16, htonl(0xC0A80000)}, 3, "node_network" },
        // RFC1918 private: 172.16.0.0/12 → label 4
        { {12, htonl(0xAC100000)}, 4, "private_172" },
        // Loopback: 127.0.0.0/8 → label 5
        { {8,  htonl(0x7F000000)}, 5, "loopback" },
    };

    for (const auto &e : entries) {
        if (bpf_map_update_elem(map_fd, &e.key, &e.label, BPF_ANY) != 0) {
            fprintf(stderr, "Warning: failed to insert CIDR %s\n", e.desc);
        }
    }

    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--help]\n", prog);
    fprintf(stderr, "\nZero-Trust Network Mapper — eBPF Collector\n");
    fprintf(stderr, "Captures TCP connection events via kprobe/tcp_v4_connect.\n");
    fprintf(stderr, "Outputs JSON lines to stdout.\n");
    fprintf(stderr, "\nRequires: root privileges, kernel >= 5.8, CONFIG_BPF=y\n");
}

int main(int argc, char **argv) {
    if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(argv[0]);
        return 0;
    }

    // Set up signal handler for clean shutdown
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open BPF object file
    struct bpf_object *obj = bpf_object__open_file("tcp_connect.bpf.o", nullptr);
    if (!obj) {
        fprintf(stderr, "Error: failed to open BPF object file\n");
        fprintf(stderr, "Make sure tcp_connect.bpf.o is in the current directory.\n");
        fprintf(stderr, "Build with: clang -O2 -target bpf -c tcp_connect.bpf.c -o tcp_connect.bpf.o\n");
        return 1;
    }

    // Load BPF programs and maps into kernel
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "Error: failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    // Attach kprobe and kretprobe
    struct bpf_program *kprobe_prog = bpf_object__find_program_by_name(obj, "tcp_v4_connect_entry");
    struct bpf_program *kretprobe_prog = bpf_object__find_program_by_name(obj, "tcp_v4_connect_return");

    if (!kprobe_prog || !kretprobe_prog) {
        fprintf(stderr, "Error: failed to find BPF programs\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_link *kprobe_link = bpf_program__attach(kprobe_prog);
    struct bpf_link *kretprobe_link = bpf_program__attach(kretprobe_prog);

    if (!kprobe_link || !kretprobe_link) {
        fprintf(stderr, "Error: failed to attach BPF programs\n");
        bpf_object__close(obj);
        return 1;
    }

    // Populate CIDR map with K8s network ranges
    struct bpf_map *cidr_map = bpf_object__find_map_by_name(obj, "cidr_map");
    if (cidr_map) {
        populate_cidr_map(bpf_map__fd(cidr_map));
    }

    // Set up ring buffer consumer
    struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "events");
    if (!events_map) {
        fprintf(stderr, "Error: failed to find events ring buffer map\n");
        bpf_link__destroy(kprobe_link);
        bpf_link__destroy(kretprobe_link);
        bpf_object__close(obj);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(events_map), handle_event, nullptr, nullptr);
    if (!rb) {
        fprintf(stderr, "Error: failed to create ring buffer\n");
        bpf_link__destroy(kprobe_link);
        bpf_link__destroy(kretprobe_link);
        bpf_object__close(obj);
        return 1;
    }

    fprintf(stderr, "Zero-Trust Mapper: eBPF collector started.\n");
    fprintf(stderr, "Capturing TCP connections... (Ctrl+C to stop)\n");

    // Main event loop — poll ring buffer
    while (!exiting) {
        int err = ring_buffer__poll(rb, 100 /* timeout_ms */);
        if (err == -EINTR) {
            break;  // Interrupted by signal
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // Cleanup
    fprintf(stderr, "\nShutting down...\n");
    ring_buffer__free(rb);
    bpf_link__destroy(kprobe_link);
    bpf_link__destroy(kretprobe_link);
    bpf_object__close(obj);

    return 0;
}
