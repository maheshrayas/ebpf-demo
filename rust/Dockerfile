ARG DEBIAN_VERSION="11.7"

FROM --platform=$BUILDPLATFORM ubuntu:24.04 as builder

RUN mkdir -p \
    /artifacts/localbin

COPY localbin/ebpf-demo /artifacts/localbin

FROM debian:${DEBIAN_VERSION}-slim

ARG TARGETPLATFORM

COPY --from=builder /artifacts/localbin/ebpf-demo /usr/local/bin

RUN apt update

RUN apt-get install -y util-linux iproute2

RUN chmod +x /usr/local/bin/ebpf-demo

ENTRYPOINT ["/usr/local/bin/ebpf-demo"]
