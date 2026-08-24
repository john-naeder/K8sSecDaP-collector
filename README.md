# K8sSecDaP-collector

eBPF collector (kernel kprobe `tcp_v4_connect` + user-space libbpf daemon) cho **K8sSecDaP**.
Bắt mọi outbound TCP connection, phân loại IP qua LPM trie (CO-RE), emit JSON events ra stdout
cho `zt-pipeline`. Đây là **data path eBPF chính thức** thay cho `tcpdump` ở chế độ live.

Output (1 dòng JSON/sự kiện, khớp đúng định dạng pipeline đọc từ stdin):
```json
{"src_ip":"10.244.1.5","dst_ip":"10.244.2.3","dst_port":8080,"pid":12345,"timestamp_ns":1234567890}
```

## Layout
- `src/kern/` — chương trình BPF (`tcp_connect.bpf.c`, CO-RE, kprobe/kretprobe).
- `src/user/` — daemon user-space (libbpf, ring buffer consumer).
- `Dockerfile` — build đa tầng: gen `vmlinux.h` → compile `.bpf.o` → build collector → runtime tối thiểu.
- `build.sh` — stage BTF của máy build vào context rồi `docker build`.
- `Makefile` — build native (chạy trực tiếp trên node để test).
- `.github/workflows/build-collector.yml` — CI build+push image (thay Tekton/kaniko).

## Yêu cầu
- Kernel target có **BTF** (`CONFIG_DEBUG_INFO_BTF=y`) — đa số distro hiện đại (Ubuntu ≥ 20.04, Fedora) đều bật.
- Kernel ≥ 5.8 (ring buffer + CO-RE). Hiện chỉ hỗ trợ **IPv4** (`tcp_v4_connect`), kiến trúc **x86_64**.

## Build container image (khuyến nghị)
```bash
./build.sh                 # stage /sys/kernel/btf/vmlinux → docker build
# IMAGE=...:tag ARCH=x86 ./build.sh   # tuỳ biến tag/arch
docker push johnnaeder/ebpf-portscan-k8s-check:collector-ebpf-s2
```
`vmlinux.h` là CO-RE portable: BTF của máy build chỉ cung cấp định nghĩa kiểu lúc biên dịch;
offset trường được relocate lúc nạp dựa trên BTF của **node đích**. Build trên kernel mới hơn
node vẫn chạy được, miễn các kiểu tham chiếu (`struct sock`, `__sk_common.skc_*`) tồn tại trên đích.

## Build native (test trên node)
```bash
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev bpftool   # Debian/Ubuntu
make            # → build/tcp_connect.bpf.o + build/collector
make run        # sudo chạy collector, in JSON ra stdout (Ctrl+C để dừng)
```

## Triển khai trong cluster
DaemonSet `K8sSecDaP-soc/manifests/23-pipeline-ebpf.yaml` chạy 3 container:
`collector` → (FIFO trên emptyDir) → `zt-pipeline` → `alert-bridge` (NATS).
Áp **22 (tcpdump) HOẶC 23 (eBPF)** trên cùng một node, **không áp cả hai** (sẽ double-emit).
```bash
kubectl apply -f K8sSecDaP-soc/manifests/23-pipeline-ebpf.yaml
kubectl -n zt-mapper logs ds/zt-pipeline-ebpf -c collector -f
```
