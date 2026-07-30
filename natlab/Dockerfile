FROM golang:1.26

RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iptables iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY . /camouflage
WORKDIR /camouflage

ENV CGO_ENABLED=0

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -tags natlab -o /usr/local/bin/natlab ./natlab

RUN cp /camouflage/natlab/topology.sh /usr/local/bin/topology.sh \
    && chmod +x /usr/local/bin/topology.sh

ENTRYPOINT ["/usr/local/bin/topology.sh"]
