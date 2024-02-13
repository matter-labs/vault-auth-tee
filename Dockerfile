FROM docker.io/ubuntu:20.04 AS pluginbuilder

ARG VERSION=1.20.4
ARG CGO_ENABLED=1
ARG BUILD_TAGS="default"
ENV JOBS=2
RUN set -eux; \
    DEBIAN_FRONTEND=noninteractive apt-get update -y; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q curl; \
    :

RUN set -eux; \
    curl -fsSLo /usr/share/keyrings/intel.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key; \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" > /etc/apt/sources.list.d/intel-sgx.list; \
    DEBIAN_FRONTEND=noninteractive apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        rsync \
        pkg-config \
        libssl-dev \
        libcurl4-openssl-dev \
        libprotobuf-dev \
        protobuf-compiler \
        clang \
        libsgx-headers \
        libsgx-dcap-quote-verify-dev \
    ; \
    :

RUN mkdir /goroot && mkdir /go
RUN curl https://storage.googleapis.com/golang/go${VERSION}.linux-amd64.tar.gz \
           | tar xvzf - -C /goroot --strip-components=1
ENV GOPATH /go
ENV GOROOT /goroot
ENV PATH $GOROOT/bin:$GOPATH/bin:$PATH

WORKDIR /

RUN --mount=type=cache,target=/root/.cache --mount=type=cache,target=/go --mount=type=bind,target=/data  \
    set -eux; \
    mkdir -p /go/src/github.com/matter-labs/vault-auth-tee; \
    cd /go/src/github.com/matter-labs/vault-auth-tee; \
    rsync -a --delete-after /data/ ./ ; \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o vault-auth-tee cmd/vault-auth-tee/main.go ; \
    mkdir -p /opt/vault/plugins; \
    cp vault-auth-tee /opt/vault/plugins/vault-auth-tee; \
    :

FROM scratch
WORKDIR /opt/vault/plugins

COPY --from=pluginbuilder /opt/vault/plugins/vault-auth-tee /opt/vault/plugins/vault-auth-tee
