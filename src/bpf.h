#pragma once

#include <stdint.h>

/** Trigger a Go panic (which will be caught and returned as an error). */
__attribute__((noreturn, import_module("env"), import_name("panic")))
extern void _env_panic(const char *msg);

/** Resolve a hostname (family: ipv4=4 ipv6=6), returning 0 on success. */
__attribute__((import_module("env"), import_name("resolve_host")))
extern int32_t _env_resolve_host(const char *hostname, int32_t family, void *out);

/** Resolve a hostname to an ethernet address, returning 0 on succes. */
__attribute__((import_module("env"), import_name("ether_hostton")))
extern int32_t _env_ether_hostton(const char *name, uint8_t out[6]);

/** Get the number of instructions in the compiled BPF program. */
__attribute__((visibility("default")))
uint32_t bpf_result_count(void);

/** Get the pointer to the instructions in the compiled BPF program.  */
__attribute__((visibility("default")))
struct bpf_insn *bpf_result_insns(void);

/** Free the compiled BPF program. */
__attribute__((visibility("default")))
void bpf_result_free(void);

/** Get the errbuf for the last failed bpf_compile. */
__attribute__((visibility("default")))
const char *bpf_errbuf(void);

__attribute__((visibility("default")))
int32_t bpf_compile(int32_t linktype, int32_t snaplen, const char *filter, int32_t optimize, uint32_t netmask);