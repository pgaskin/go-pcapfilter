#pragma once

#include <stdio.h>
#include "bpf.h"

typedef int jmp_buf[1]; // dummy

static __attribute__((noreturn, unused))
void _pcap_longjmp_at(const char *func, const char *file, int line) {
    static char _buf[256];
    snprintf(_buf, sizeof(_buf), "unimplemented longjmp in %s at %s:%d", func, file, line);
    _env_panic(_buf);
}

#define setjmp(env) 0
#define longjmp(env, v) _pcap_longjmp_at(__func__, __FILE__, __LINE__)
