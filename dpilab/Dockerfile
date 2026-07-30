# nDPI is built from source: no distro ships ndpiReader, and the flow-risk
# names the verdict matches on are only stable within one release, so the tag
# is pinned.
FROM golang:1.26 AS ndpi

ARG NDPI_REF=5.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates build-essential autoconf automake libtool pkg-config \
      libpcap-dev flex bison libjson-c-dev libgcrypt20-dev libnuma-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "$NDPI_REF" https://github.com/ntop/nDPI /src/nDPI \
    && cd /src/nDPI \
    && ./autogen.sh \
    && ./configure \
    && make -j"$(nproc)"

FROM golang:1.26

RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping ethtool tcpdump \
      libpcap0.8 libjson-c5 libgcrypt20 libnuma1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ndpi /src/nDPI/example/ndpiReader /usr/local/bin/ndpiReader

COPY . /camouflage
WORKDIR /camouflage

ENV CGO_ENABLED=0

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -tags dpilab -o /usr/local/bin/dpilab ./dpilab

RUN cp /camouflage/dpilab/lab.sh /usr/local/bin/lab.sh && chmod +x /usr/local/bin/lab.sh

ENTRYPOINT ["/usr/local/bin/lab.sh"]
