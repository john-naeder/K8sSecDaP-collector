// Pod / container metadata resolution — offline, from /proc.
//
// The kernel knows cgroup_id + pid + comm but NOT the Kubernetes pod or
// namespace names. This unit recovers them in user space without any K8s API
// call, by reading the offending process's /proc entries:
//
//   container_id, pod_uid : parsed from /proc/<pid>/cgroup (kubepods path)
//   namespace             : /proc/<pid>/root/var/run/secrets/.../namespace
//   pod_name              : /proc/<pid>/root/etc/hostname (best-effort)
//
// The pure parsers (parse_cgroup_line) are split out so they can be unit-tested
// with fixture strings, no live /proc required.

#pragma once
#include <cstdint>
#include <string>

namespace ztmeta {

struct PodMeta {
    std::string pod_name;
    std::string namespace_;
    std::string container_id;
    std::string pod_uid;
};

// Parse a single line of /proc/<pid>/cgroup, extracting the container id and
// pod uid when the line points into the kubepods hierarchy. Handles both
// cgroup v1 ("3:cpu:/kubepods/...") and v2 ("0::/kubepods.slice/...") layouts,
// and the containerd (cri-containerd-<id>.scope), CRI-O (crio-<id>.scope) and
// plain (<64hex>) container forms.
//
// Returns true and fills container_id (+ pod_uid when present) on a kubepods
// line; returns false for non-kubepods lines (host processes).
bool parse_cgroup_line(const std::string& line,
                       std::string& container_id,
                       std::string& pod_uid);

// Resolve full pod metadata for a process by reading its /proc entries.
// `proc_root` defaults to "/proc"; overridable for tests. Best-effort: any
// field that cannot be resolved is left empty.
PodMeta resolve_pod_meta(uint32_t pid, const std::string& proc_root = "/proc");

} // namespace ztmeta
