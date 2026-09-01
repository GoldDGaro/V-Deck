# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 AS builder

ARG GO_VERSION=1.25.14
ARG GO_SHA256=a21ae5633a269bcd7e90cf767e48225633795e99d831742cbf3397064fee7712
ARG AWG_GO_TAG=v3.1.20260828
ARG AWG_TOOLS_TAG=v3.1.20260812
ARG WG_GO_TAG=0.0.20250522
ARG WG_TOOLS_TAG=v1.0.20260223
ARG OPENVPN_TAG=v2.7.6
ARG WOLFSSL_TAG=v5.9.2-stable
ARG AWG_GO_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e
ARG AWG_TOOLS_COMMIT=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
ARG WG_GO_COMMIT=f333402bd9cbe0f3eeb02507bd14e23d7d639280
ARG WG_TOOLS_COMMIT=49ce333da02056ae7b22ee2aeb6afe8aaed79b19
ARG OPENVPN_COMMIT=327a33de2aa21883f3d206774c1d0801b244fce6
ARG WOLFSSL_COMMIT=ac01707f552c611fbd135cc723b2682b3e7f80f2

RUN apk add --no-cache \
    autoconf=2.72-r1 automake=1.17-r1 bash=5.2.37-r0 \
    binutils=2.44-r3 build-base=0.5-r3 ca-certificates=20260611-r0 \
    curl=8.14.1-r3 g++=14.2.0-r6 gcc=14.2.0-r6 git=2.49.1-r0 \
    libcap-ng=0.8.5-r0 libcap-ng-dev=0.8.5-r0 libcap-ng-static=0.8.5-r0 \
    libtool=2.5.4-r1 linux-headers=6.14.2-r0 m4=1.4.19-r4 \
    make=4.4.1-r3 musl=1.2.5-r12 musl-dev=1.2.5-r12 \
    pax-utils=1.3.8-r1 perl=5.40.4-r0 pkgconf=2.4.3-r0

RUN curl --fail --location --proto '=https' --tlsv1.2 \
      "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz \
    && echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

ENV PATH=/usr/local/go/bin:${PATH} \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    GOFLAGS=-buildvcs=false

WORKDIR /src
RUN git clone --depth 1 --branch "${AWG_GO_TAG}" https://github.com/amnezia-vpn/amneziawg-go.git \
    && git clone --depth 1 --branch "${AWG_TOOLS_TAG}" https://github.com/amnezia-vpn/amneziawg-tools.git \
    && git clone --depth 1 --branch "${WG_GO_TAG}" https://git.zx2c4.com/wireguard-go \
    && git clone --depth 1 --branch "${WG_TOOLS_TAG}" https://git.zx2c4.com/wireguard-tools \
    && git clone --depth 1 --branch "${WOLFSSL_TAG}" https://github.com/wolfSSL/wolfssl.git \
    && git clone --depth 1 --branch "${OPENVPN_TAG}" https://github.com/OpenVPN/openvpn.git

RUN test "$(git -C /src/amneziawg-go rev-parse HEAD)" = "${AWG_GO_COMMIT}" \
    && test "$(git -C /src/amneziawg-tools rev-parse HEAD)" = "${AWG_TOOLS_COMMIT}" \
    && test "$(git -C /src/wireguard-go rev-parse HEAD)" = "${WG_GO_COMMIT}" \
    && test "$(git -C /src/wireguard-tools rev-parse HEAD)" = "${WG_TOOLS_COMMIT}" \
    && test "$(git -C /src/openvpn rev-parse HEAD)" = "${OPENVPN_COMMIT}" \
    && test "$(git -C /src/wolfssl rev-parse HEAD)" = "${WOLFSSL_COMMIT}"

COPY backend/amneziawg-go-version.patch /tmp/amneziawg-go-version.patch
COPY backend/amneziawg-tools-bundled-uapi.patch /tmp/amneziawg-tools-bundled-uapi.patch
COPY backend/wireguard-tools-bundled-uapi.patch /tmp/wireguard-tools-bundled-uapi.patch
COPY backend/openvpn-static-cmake.patch /tmp/openvpn-static-cmake.patch
COPY backend/openvpn-static-autotools.patch /tmp/openvpn-static-autotools.patch
RUN git -C /src/amneziawg-go apply /tmp/amneziawg-go-version.patch \
    && git -C /src/amneziawg-tools apply /tmp/amneziawg-tools-bundled-uapi.patch \
    && git -C /src/wireguard-tools apply /tmp/wireguard-tools-bundled-uapi.patch \
    && git -C /src/openvpn apply /tmp/openvpn-static-cmake.patch \
    && git -C /src/openvpn apply /tmp/openvpn-static-autotools.patch \
    && mkdir -p /out \
    && cd /src/amneziawg-go \
    && go build -tags unix -trimpath -ldflags='-s -w' -o /out/amneziawg-go . \
    && cd /src/wireguard-go \
    && go build -trimpath -ldflags='-s -w' -o /out/wireguard-go .

ENV CGO_ENABLED=1
RUN make -C /src/amneziawg-tools/src -j"$(nproc)" \
      CFLAGS='-O3 -fPIE -DRUNSTATEDIR=\"/run\"' LDFLAGS='-static -s' WITH_WGQUICK=no WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no \
    && install -m 0755 /src/amneziawg-tools/src/wg /out/awg \
    && make -C /src/wireguard-tools/src -j"$(nproc)" \
      CFLAGS='-O3 -fPIE -DRUNSTATEDIR=\"/run\"' LDFLAGS='-static -s' WITH_WGQUICK=no WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no \
    && install -m 0755 /src/wireguard-tools/src/wg /out/wg

RUN cd /src/wolfssl \
    && ./autogen.sh \
    && ./configure --prefix=/opt/vdeck --enable-openvpn --disable-shared --enable-static \
       --disable-examples --disable-crypttests CFLAGS='-O2 -fPIE' LDFLAGS='-static' \
    && make -j"$(nproc)" \
    && make install

RUN cd /src/openvpn \
    && autoreconf -vi \
    && PKG_CONFIG_PATH=/opt/vdeck/lib/pkgconfig ./configure \
       --with-crypto-library=wolfssl --disable-shared --enable-static \
       --disable-dco --disable-lzo --disable-lz4 --disable-pkcs11 \
       --disable-plugin-auth-pam --disable-plugin-down-root \
       --disable-selinux --disable-systemd \
       WOLFSSL_CFLAGS='-I/opt/vdeck/include -I/opt/vdeck/include/wolfssl' \
       WOLFSSL_LIBS='-lwolfssl -lm' \
       CFLAGS='-O2 -fPIE' LDFLAGS='-static -L/opt/vdeck/lib' \
    && make -j"$(nproc)" \
    && install -m 0755 src/openvpn/openvpn /out/openvpn \
    && strip /out/openvpn /out/awg /out/wg \
    && file /out/* \
    && ! scanelf -n /out/* | grep -E 'lib(c|m|pthread|wolfssl|cap-ng)\.so'

FROM scratch AS binaries
COPY --from=builder /out/ /
