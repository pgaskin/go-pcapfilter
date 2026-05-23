#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
 
#include <pcap/pcap.h>

#include "pcap-dummy.h"
#include "bpf.h"

#define unused __attribute__((unused))

static struct bpf_program program;
static char errbuf[PCAP_ERRBUF_SIZE + 1];
static pcap_t *failed = NULL; // so we don't need longjmp for error handling

int32_t bpf_compile(int32_t linktype, int32_t snaplen, const char *filter, int32_t optimize, uint32_t netmask) {
    pcap_freecode(&program);
    errbuf[0] = '\0';

    pcap_t *p = pcap_open_dummy(linktype, snaplen);
    if (p == NULL) {
        snprintf(errbuf, sizeof(errbuf), "out of memory");
        return -1;
    }

    failed = p;
    int rc = pcap_compile(p, &program, filter, optimize, (bpf_u_int32)netmask);
    failed = NULL;

    if (rc != 0) {
        snprintf(errbuf, sizeof(errbuf), "%s", _pcap_errbuf(p));
        pcap_close(p);
        return -1;
    }

    pcap_close(p);
    return 0;
}

uint32_t bpf_result_count(void) {
    return program.bf_len;
}

struct bpf_insn *bpf_result_insns(void) {
    return program.bf_insns;
}

void bpf_result_free(void) {
    pcap_freecode(&program);
}

const char *bpf_errbuf(void) {
    // errbuf is set by bpf_error() before the longjmp, so prefer it over the
    // global one
    if (failed && *_pcap_errbuf(failed)) {
        return _pcap_errbuf(failed);
    }
    return errbuf;
}

// used by flex on oom
void exit(unused int status) { _env_panic("unexpected exit"); }
void abort(void) { _env_panic("unexpected abort"); }

// avoid bringing in wasi stuff for unused stdio FILE* operations
ssize_t readv(unused int fd, unused const struct iovec *iov, unused int cnt) { return -1; }
ssize_t writev(unused int fd, unused const struct iovec *iov, unused int cnt) { return -1; }
ssize_t read(unused int fd, unused void *buf, unused size_t n) { return -1; }
off_t __lseek(unused int fd, unused off_t offset, unused int whence) { return -1; }
int __isatty(unused int fd) { return 0; }
int close(unused int fd) { return 0; }
