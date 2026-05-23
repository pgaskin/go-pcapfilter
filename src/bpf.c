#include <stdio.h>
#include <pcap/pcap.h>

#include "pcap-dummy.h"
#include "bpf.h"

#define unused __attribute__((unused))

static struct bpf_program program;
static char errbuf[PCAP_ERRBUF_SIZE + 1];
static pcap_t *failed = NULL; // so we don't need longjmp for error handling

struct bpf_compile_result bpf_compile(int32_t linktype, int32_t snaplen, const char *filter, int32_t optimize, uint32_t netmask) {
    pcap_freecode(&program);
    errbuf[0] = '\0';

    pcap_t *p = pcap_open_dummy(linktype, snaplen);
    if (p == NULL) {
        snprintf(errbuf, sizeof(errbuf), "out of memory");
        return (struct bpf_compile_result){ -1, NULL };
    }

    failed = p;
    int rc = pcap_compile(p, &program, filter, optimize, (bpf_u_int32)netmask);
    failed = NULL;

    if (rc != 0) {
        snprintf(errbuf, sizeof(errbuf), "%s", _pcap_errbuf(p));
        pcap_close(p);
        return (struct bpf_compile_result){ -1, NULL };
    }

    pcap_close(p);
    return (struct bpf_compile_result){ (int32_t)program.bf_len, program.bf_insns };
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

// flex calls exit on OOM
void exit(unused int status) { _env_panic("unexpected exit"); }

// stub unused stdio FILE* operations from stdio.h
int fclose(unused void *stream) { return 0; }
int fseek(unused void *stream, unused long offset, unused int whence) { return -1; }
size_t fwrite(unused const void *ptr, unused size_t size, unused size_t n, unused void *stream) { return 0; }
size_t fread(unused void *ptr, unused size_t size, unused size_t n, unused void *stream) { return 0; }
int fgetc(unused void *stream) { return -1; }
int getc(unused void *stream) { return -1; }
int ferror(unused void *stream) { return 0; }
void clearerr(unused void *stream) {}
char *fgets(unused char *s, unused int n, unused void *stream) { return NULL; }
void *fopen(unused const char *path, unused const char *mode) { return NULL; }
int fputc(unused int c, unused void *stream) { return -1; }
int fflush(unused void *stream) { return 0; }
long ftell(unused void *stream) { return -1; }
