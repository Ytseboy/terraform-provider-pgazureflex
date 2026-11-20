FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

ENV ELAN_HOME=/usr/local/elan
ENV PATH=/usr/local/elan/bin:$PATH

COPY formal/lean-toolchain /tmp/lean-toolchain
RUN curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
    | sh -s -- -y --default-toolchain "$(cat /tmp/lean-toolchain)" --no-modify-path \
    && lean --version \
    && rm -f /tmp/lean-toolchain

WORKDIR /workspace/formal
