# go-pcapfilter

[![Go Reference](https://pkg.go.dev/badge/github.com/pgaskin/go-pcapfilter.svg)](https://pkg.go.dev/github.com/pgaskin/go-pcapfilter)
[![Test](https://github.com/pgaskin/go-pcapfilter/actions/workflows/test.yml/badge.svg)](https://github.com/pgaskin/go-pcapfilter/actions/workflows/test.yml)
[![Attest libpcap build](https://github.com/pgaskin/go-pcapfilter/actions/workflows/attest.yml/badge.svg)](https://github.com/pgaskin/go-pcapfilter/actions/workflows/attest.yml)

Compile tcpdump-style filters in pure Go.

This library wraps a WebAssembly build of [pcap_compile](https://www.tcpdump.org/manpages/pcap_compile.3pcap.html) from [libpcap](https://github.com/the-tcpdump-group/libpcap) transpiled to Go using [wasm2go](https://github.com/ncruces/wasm2go).

It can be used with libraries like [github.com/gopacket/gopacket/afpacket](https://github.com/google/gopacket/tree/master/afpacket) to implement CGO-less packet capture.

A command-line interface is available.

The wasm2go blob is fully [reproducible](./src/Dockerfile) and [verified](https://github.com/pgaskin/go-pcapfilter/attestations).

To have working IDE integration while working on the bindings, use `bear -- make -C src distclean download all CC=/path/to/wasi-sdk/bin/wasm32-wasip1-clang WASM_OPT=/path/to/binaryen/bin/wasm-opt` to download the libpcap source and generate the `compile_commands.json`.
