#!/bin/bash


#kubectl create ns kube-guardian

## Install DB


### BUILD API
cargo install bpf-linker

aya-tool generate task_struct > ebpf-demo-ebpf/src/vmlinux.rs


cargo install cross --git https://github.com/cross-rs/cross

          # # # build ebpf byte code
cargo xtask build-ebpf --release

cross build --target x86_64-unknown-linux-gnu --release

mkdir -p localbin

cp ./target/x86_64-unknown-linux-gnu/release/ebpf-demo ./localbin/

DOCKER_BUILDKIT=1 docker build . -f Dockerfile -t maheshrayas/ebpf-syscalls:v0.8.82
docker push maheshrayas/ebpf-syscalls:v0.8.82
# kind load docker-image maheshrayas/ebpf-syscalls:v0.2.0

kubectl apply -f kubernetes.yaml


