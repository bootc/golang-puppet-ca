# ---- Build Stage ----
FROM quay.io/centos/centos:stream10 AS builder

RUN dnf install -y golang git && dnf clean all

WORKDIR /src
COPY go.mod go.sum ./
# GOTOOLCHAIN=auto lets Go download the exact version required by go.mod
# (the distro-packaged Go bootstraps the download).
RUN GOTOOLCHAIN=auto go mod download

COPY . .
ENV GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux
RUN go build -ldflags="-s -w" -o /openvox-ca     ./cmd/openvox-ca/ && \
    go build -ldflags="-s -w" -o /openvox-ca-ctl ./cmd/openvox-ca-ctl/

# ---- Runtime Stage ----
FROM quay.io/centos/centos:stream10

# curl: health checks and agent CSR submission
# openssl: CSR generation and cert verification in integration tests
#
# The puppet uid/gid is pinned to 1000 rather than left to useradd's first-free
# allocation: `USER` below has to be numeric so a host that cannot read the
# image's /etc/passwd -- Kubernetes checking `runAsNonRoot`, or an operator
# matching ownership on a bind mount -- can still tell who the process runs as.
# 1000 is what useradd picks today, so the runtime identity is unchanged.
RUN dnf install -y curl openssl && dnf clean all && \
    groupadd -g 1000 puppet && \
    useradd -m -u 1000 -g 1000 puppet && \
    { [ "$(id -u puppet):$(id -g puppet)" = "1000:1000" ] || \
        { echo "puppet is $(id -u puppet):$(id -g puppet), not 1000:1000; USER below must match" >&2; exit 1; }; } && \
    mkdir -p /etc/puppetlabs/puppet/ssl/ca /data && \
    chown -R puppet:puppet /etc/puppetlabs/puppet /data

COPY --from=builder /openvox-ca     /usr/local/bin/openvox-ca
COPY --from=builder /openvox-ca-ctl /usr/local/bin/openvox-ca-ctl

USER 1000:1000
EXPOSE 8140

# --cadir             : where CA state is stored
# --verbosity         : debug logging
#
# NOTE: autosign is OFF by default. Set --autosign-config=true only in
# dev/test environments. Autosign lets any CSR submitter obtain a signed
# certificate without operator review.
ENTRYPOINT ["/usr/local/bin/openvox-ca"]
CMD ["--cadir=/etc/puppetlabs/puppet/ssl/ca", \
     "--verbosity=1"]
