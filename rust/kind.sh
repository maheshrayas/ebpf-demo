#!/bin/bash

cargo install bpf-linker

cargo install cross --git https://github.com/cross-rs/cross

# generate bindings(task_struct)
cargo xtask codegen 

# build ebpf byte code
cargo xtask build-ebpf --release

cross build --target x86_64-unknown-linux-gnu --release

mkdir -p localbin

cp ./target/x86_64-unknown-linux-gnu/release/ebpf-demo ./localbin/

DOCKER_BUILDKIT=1 docker build . -f Dockerfile -t maheshrayas/ebpf-syscalls:v0.8.52

docker push maheshrayas/ebpf-syscalls:v0.8.52

#kind load docker-image maheshrayas/ebpf-syscalls:v0.8.63

kubectl apply -f kubernetes.yaml


