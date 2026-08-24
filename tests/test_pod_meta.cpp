// Unit tests for the offline pod-metadata parsers (no gtest dependency —
// plain asserts so it builds with just clang++).
//
//   make test

#include "pod_meta.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

using ztmeta::parse_cgroup_line;
using ztmeta::resolve_pod_meta;
using ztmeta::PodMeta;

static int g_checks = 0;
#define CHECK(cond) do { ++g_checks; if (!(cond)) { \
    std::fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
    std::exit(1); } } while (0)

static void test_containerd_systemd_driver() {
    // Typical cgroup v2 line, systemd driver, containerd runtime.
    std::string line =
        "0::/kubepods.slice/kubepods-besteffort.slice/"
        "kubepods-besteffort-pod1234abcd_5678_ef90_1234_567890abcdef.slice/"
        "cri-containerd-"
        "9f8c7b6a5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a.scope";
    std::string cid, uid;
    bool ok = parse_cgroup_line(line, cid, uid);
    CHECK(ok);
    CHECK(cid == "9f8c7b6a5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a");
    // Underscores in the pod uid are normalised to dashes.
    CHECK(uid == "1234abcd-5678-ef90-1234-567890abcdef");
}

static void test_crio_runtime() {
    std::string line =
        "0::/kubepods.slice/kubepods-podaaaa1111_bbbb_2222_cccc_333344445555.slice/"
        "crio-"
        "0011223344556677889900112233445566778899001122334455667788990011.scope";
    std::string cid, uid;
    bool ok = parse_cgroup_line(line, cid, uid);
    CHECK(ok);
    CHECK(cid == "0011223344556677889900112233445566778899001122334455667788990011");
    CHECK(uid == "aaaa1111-bbbb-2222-cccc-333344445555");
}

static void test_cgroupfs_driver_v1() {
    // cgroup v1 line, cgroupfs driver: pod uid segment is "pod<uid>", container
    // segment is the bare 64-hex id.
    std::string line =
        "4:cpu,cpuacct:/kubepods/besteffort/"
        "podabcdef01-2345-6789-abcd-ef0123456789/"
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    std::string cid, uid;
    bool ok = parse_cgroup_line(line, cid, uid);
    CHECK(ok);
    CHECK(cid == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    CHECK(uid == "abcdef01-2345-6789-abcd-ef0123456789");
}

static void test_host_process_not_kubepods() {
    std::string line = "0::/system.slice/sshd.service";
    std::string cid, uid;
    bool ok = parse_cgroup_line(line, cid, uid);
    CHECK(!ok);
    CHECK(cid.empty());
    CHECK(uid.empty());
}

static void test_malformed_line() {
    std::string cid, uid;
    CHECK(!parse_cgroup_line("garbage-no-colons", cid, uid));
    CHECK(!parse_cgroup_line("", cid, uid));
}

static void test_resolve_from_fixture_proc() {
    // Build a fake /proc/<pid> tree and resolve against it.
    const std::string root = "/tmp/ztmeta_test_proc";
    const std::string pid  = "4242";
    const std::string base = root + "/" + pid;
    std::system(("rm -rf " + root).c_str());
    std::system(("mkdir -p " + base +
                 "/root/var/run/secrets/kubernetes.io/serviceaccount").c_str());
    std::system(("mkdir -p " + base + "/root/etc").c_str());

    {
        std::ofstream f(base + "/cgroup");
        f << "0::/kubepods.slice/kubepods-besteffort.slice/"
             "kubepods-besteffort-pod1111aaaa_2222_bbbb_3333_ccccddddeeee.slice/"
             "cri-containerd-"
             "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab.scope\n";
    }
    {
        std::ofstream f(base +
            "/root/var/run/secrets/kubernetes.io/serviceaccount/namespace");
        f << "prod\n";
    }
    {
        std::ofstream f(base + "/root/etc/hostname");
        f << "frontend-7d9c\n";
    }

    PodMeta m = resolve_pod_meta(4242, root);
    CHECK(m.container_id ==
          "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab");
    CHECK(m.pod_uid == "1111aaaa-2222-bbbb-3333-ccccddddeeee");
    CHECK(m.namespace_ == "prod");
    CHECK(m.pod_name == "frontend-7d9c");

    std::system(("rm -rf " + root).c_str());
}

static void test_resolve_host_process_empty() {
    const std::string root = "/tmp/ztmeta_test_proc2";
    const std::string base = root + "/99";
    std::system(("rm -rf " + root).c_str());
    std::system(("mkdir -p " + base).c_str());
    {
        std::ofstream f(base + "/cgroup");
        f << "0::/system.slice/sshd.service\n";
    }
    PodMeta m = resolve_pod_meta(99, root);
    CHECK(m.container_id.empty());
    CHECK(m.namespace_.empty());
    // pod_name falls back to pod_uid, which is also empty here.
    CHECK(m.pod_name.empty());
    std::system(("rm -rf " + root).c_str());
}

int main() {
    test_containerd_systemd_driver();
    test_crio_runtime();
    test_cgroupfs_driver_v1();
    test_host_process_not_kubepods();
    test_malformed_line();
    test_resolve_from_fixture_proc();
    test_resolve_host_process_empty();
    std::printf("OK — %d checks passed\n", g_checks);
    return 0;
}
