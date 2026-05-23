FROM golang:1.25-trixie AS base

ARG WASI_SDK_VERSION=30
ARG FLEX_VERSION=2.6.4
ARG BISON_VERSION=3.8.2

ARG WASI_SDK_CHECKSUM=sha256:0507679dff16814b74516cd969a9b16d2ced1347388024bc7966264648c78bfb
ARG FLEX_CHECKSUM=sha256:e87aae032bf07c26f85ac0ed3250998c37621d95f8bd748b31f15b33c45ee995
ARG BISON_CHECKSUM=sha256:06c9e13bdf7eb24d4ceb6b59205a4f67c2c7e7213119644430fe82fbd14a0abb

ARG WASI_SDK_URL=https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VERSION}/wasi-sdk-${WASI_SDK_VERSION}.0-x86_64-linux.tar.gz
ARG FLEX_URL=https://github.com/westes/flex/releases/download/v${FLEX_VERSION}/flex-${FLEX_VERSION}.tar.gz
ARG BISON_URL=https://ftp.gnu.org/gnu/bison/bison-${BISON_VERSION}.tar.gz

FROM base AS wasi-sdk
ADD --checksum=${WASI_SDK_CHECKSUM} ${WASI_SDK_URL} /wasi-sdk.tar.gz
RUN mkdir /opt/wasi-sdk && tar -C /opt/wasi-sdk --strip-components=1 -xf /wasi-sdk.tar.gz

FROM base AS flex
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential m4
ADD --checksum=${FLEX_CHECKSUM} ${FLEX_URL} /flex.tar.gz
RUN mkdir /src && tar -C /src --strip-components=1 -xf /flex.tar.gz
RUN cd /src && ./configure --prefix=/opt/flex && make -j$(nproc) && make install

FROM base AS bison
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential m4
ADD --checksum=${BISON_CHECKSUM} ${BISON_URL} /bison.tar.gz
RUN mkdir /src && tar -C /src --strip-components=1 -xf /bison.tar.gz
RUN cd /src && ./configure --prefix=/opt/bison && make -j$(nproc) && make install

FROM base AS wasm2go-version
COPY --link Makefile /
RUN grep -oE 'github.com/ncruces/wasm2go@v[0-9.]+' /Makefile > /wasm2go.txt

FROM base AS wasm2go
COPY --link --from=wasm2go-version /wasm2go.txt /
RUN GOBIN=/ go install -trimpath -v $(cat /wasm2go.txt)

FROM base AS sdk
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y make m4
COPY --link --from=wasi-sdk /opt /opt
COPY --link --from=flex /opt/flex /opt/flex
COPY --link --from=bison /opt/bison /opt/bison
COPY --link --from=wasm2go /wasm2go /usr/local/bin/
ENV PATH="/opt/wasi-sdk/bin:/opt/flex/bin:/opt/bison/bin:$PATH"

FROM base AS download
WORKDIR /build/src
COPY --link download.go /build/src/
RUN go run download.go

FROM sdk AS build
WORKDIR /build/

COPY --from=download /build/src/libpcap/ /build/src/libpcap/
COPY --link bpf.c bpf.h config.h constgen.go Makefile netdb.c netdb.h pcap-dummy.c pcap-dummy.h setjmp.h signal.h /build/src/
RUN mkdir internal && make -j$(nproc) -Csrc all WASM2GO=wasm2go

FROM scratch
COPY --link --from=build /build/internal/ /internal/
