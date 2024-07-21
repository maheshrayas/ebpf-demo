#!/bin/bash
kind create cluster --config=./kind.yaml | exit 0

echo "wait until cluster is created!"

sleep 60

curl -LO https://github.com/cilium/cilium/archive/main.tar.gz
tar xzf main.tar.gz
cd cilium-main/install/kubernetes

docker pull quay.io/cilium/cilium:v1.15
kind load docker-image quay.io/cilium/cilium:v1.15