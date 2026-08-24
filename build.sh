#!/usr/bin/env bash
# Stage the build machine's kernel BTF into the Docker context, then build the
# collector image. Works on any host/CI runner whose kernel has BTF
# (CONFIG_DEBUG_INFO_BTF=y) — no bpftool needed on the host (the builder image
# has it). The image is CO-RE portable across kernels.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="${IMAGE:-johnnaeder/ebpf-portscan-k8s-check:collector-ebpf-s2}"
BTF_SRC="${BTF_SRC:-/sys/kernel/btf/vmlinux}"
ARCH="${ARCH:-x86}"

if [[ ! -r "$BTF_SRC" ]]; then
    echo "ERROR: kernel BTF not readable at $BTF_SRC" >&2
    echo "       Need a kernel built with CONFIG_DEBUG_INFO_BTF=y." >&2
    exit 1
fi

mkdir -p btf
install -m 0644 "$BTF_SRC" btf/vmlinux   # overwrites read-only dest on re-run
echo "[build] staged BTF from $BTF_SRC ($(stat -c%s btf/vmlinux) bytes), ARCH=$ARCH"

docker build --build-arg ARCH="$ARCH" -t "$IMAGE" .
echo "[build] built $IMAGE"
echo "[build] push with: docker push $IMAGE"
