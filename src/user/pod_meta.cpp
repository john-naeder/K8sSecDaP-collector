#include "pod_meta.h"

#include <fstream>
#include <sstream>

namespace ztmeta {

namespace {

// Trim trailing whitespace/newlines (hostname/namespace files end with '\n').
std::string rstrip(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' ||
                          s.back() == ' '  || s.back() == '\t')) {
        s.pop_back();
    }
    return s;
}

// Is `s` a plausible container id: long lower-hex run (>= 32 chars)?
bool looks_like_container_id(const std::string& s) {
    if (s.size() < 32) return false;
    for (char c : s) {
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
    }
    return true;
}

// Extract a pod uid out of a path segment like:
//   kubepods-besteffort-pod<UID>.slice   (systemd cgroup driver)
//   pod<UID>                             (cgroupfs driver)
// where <UID> is a uuid with '_' or '-' separators. Normalises '_' → '-'.
std::string extract_pod_uid(const std::string& segment) {
    // Use rfind so we match the real "...-pod<UID>" / "pod<UID>" segment and
    // not the "pod" inside the parent "kubepods" slice.
    auto pos = segment.rfind("pod");
    if (pos == std::string::npos) return "";
    std::string uid = segment.substr(pos + 3);
    // Strip a trailing ".slice" / ".scope" if present.
    auto dot = uid.find('.');
    if (dot != std::string::npos) uid = uid.substr(0, dot);
    // A pod uid is a uuid: hex digits plus '-'/'_' separators, >= 32 chars.
    // This rejects accidental matches like the "pods" in "kubepods-besteffort".
    if (uid.size() < 32) return "";
    for (char& c : uid) {
        if (c == '_') c = '-';
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-';
        if (!ok) return "";
    }
    return uid;
}

// Pull the container id out of the last path segment.
std::string extract_container_id(const std::string& segment) {
    std::string s = segment;
    // Drop a trailing ".scope" / ".slice".
    auto dot = s.find('.');
    if (dot != std::string::npos) s = s.substr(0, dot);
    // Strip known runtime prefixes: "cri-containerd-", "crio-", "docker-".
    for (const char* pfx : {"cri-containerd-", "crio-", "docker-", "containerd-"}) {
        std::string p(pfx);
        if (s.rfind(p, 0) == 0) { s = s.substr(p.size()); break; }
    }
    return looks_like_container_id(s) ? s : "";
}

} // namespace

bool parse_cgroup_line(const std::string& line,
                       std::string& container_id,
                       std::string& pod_uid) {
    container_id.clear();
    pod_uid.clear();

    // cgroup line format: "hierarchy-ID:controller-list:cgroup-path".
    // The path is everything after the second ':'.
    auto first = line.find(':');
    if (first == std::string::npos) return false;
    auto second = line.find(':', first + 1);
    if (second == std::string::npos) return false;
    std::string path = line.substr(second + 1);

    if (path.find("kubepods") == std::string::npos) return false;

    // Split the path into '/'-separated segments; the last is the container,
    // an earlier "pod<UID>" segment carries the pod uid.
    std::istringstream iss(path);
    std::string seg, last_seg;
    while (std::getline(iss, seg, '/')) {
        if (seg.empty()) continue;
        if (pod_uid.empty()) {
            std::string u = extract_pod_uid(seg);
            if (!u.empty()) pod_uid = u;
        }
        last_seg = seg;
    }

    container_id = extract_container_id(last_seg);
    // Treat as a kubepods line if we recovered either identifier.
    return !container_id.empty() || !pod_uid.empty();
}

PodMeta resolve_pod_meta(uint32_t pid, const std::string& proc_root) {
    PodMeta meta;
    const std::string base = proc_root + "/" + std::to_string(pid);

    // 1. container_id + pod_uid from /proc/<pid>/cgroup
    {
        std::ifstream f(base + "/cgroup");
        std::string line;
        while (std::getline(f, line)) {
            std::string cid, uid;
            if (parse_cgroup_line(line, cid, uid)) {
                if (!cid.empty()) meta.container_id = cid;
                if (!uid.empty()) meta.pod_uid = uid;
                break;
            }
        }
    }

    // 2. namespace from the pod's mounted service-account token dir
    {
        std::ifstream f(base +
            "/root/var/run/secrets/kubernetes.io/serviceaccount/namespace");
        std::string ns;
        if (f && std::getline(f, ns)) meta.namespace_ = rstrip(ns);
    }

    // 3. pod_name (best-effort): the pod hostname defaults to the pod name.
    {
        std::ifstream f(base + "/root/etc/hostname");
        std::string h;
        if (f && std::getline(f, h)) meta.pod_name = rstrip(h);
    }
    if (meta.pod_name.empty()) meta.pod_name = meta.pod_uid;  // fallback

    return meta;
}

} // namespace ztmeta
