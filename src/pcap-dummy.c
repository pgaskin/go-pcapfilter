#include <ctype.h>
#include <stdlib.h>

#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <pcap/namedb.h>

#include "config.h"
#include "pcap-int.h"

#include "bpf.h"

#ifdef PACKAGE_NAME
// so clang doesn't complain about config.h not being used
#endif

#define unused __attribute__((unused))

// stubs
static int pcap_cant_set_rfmon_dummy(unused pcap_t *p) { return 0; }
static int pcap_read_dummy(unused pcap_t *p, unused int cnt, unused pcap_handler cb, unused u_char *u) { return -1; }
static int pcap_inject_dummy(unused pcap_t *p, unused const void *b, unused int s) { return -1; }
static int pcap_setfilter_dummy(unused pcap_t *p, unused struct bpf_program *fp) { return -1; }
static int pcap_setdirection_dummy(unused pcap_t *p, unused pcap_direction_t d) { return -1; }
static int pcap_set_datalink_dummy(unused pcap_t *p, unused int dlt) { return -1; }
static int pcap_getnonblock_dummy(unused pcap_t *p) { return -1; }
static int pcap_setnonblock_dummy(unused pcap_t *p, unused int nb) { return -1; }
static int pcap_stats_dummy(unused pcap_t *p, unused struct pcap_stat *ps) { return -1; }
static void pcap_breakloop_dummy(unused pcap_t *p) {}
static void pcap_cleanup_dummy(unused pcap_t *p) {}

// dummy pcap open with enough to compile filters
pcap_t *pcap_open_dummy(int linktype, int snaplen) {
    pcap_t *p = calloc(1, sizeof(*p));
    if (p == NULL) {
        return NULL;
    }
    p->snapshot                 = snaplen;
    p->linktype                 = linktype;
    p->opt.tstamp_precision     = PCAP_TSTAMP_PRECISION_MICRO;
    p->can_set_rfmon_op         = pcap_cant_set_rfmon_dummy;
    p->read_op                  = pcap_read_dummy;
    p->inject_op                = pcap_inject_dummy;
    p->setfilter_op             = pcap_setfilter_dummy;
    p->setdirection_op          = pcap_setdirection_dummy;
    p->set_datalink_op          = pcap_set_datalink_dummy;
    p->getnonblock_op           = pcap_getnonblock_dummy;
    p->setnonblock_op           = pcap_setnonblock_dummy;
    p->stats_op                 = pcap_stats_dummy;
    p->breakloop_op             = pcap_breakloop_dummy;
    p->cleanup_op               = pcap_cleanup_dummy;
    p->bpf_codegen_flags        = 0;
    p->activated                = 1;
    return p;
}

pcap_t *pcap_open_dummy_with_tstamp_precision(int linktype, int snaplen, unused u_int precision) {
    return pcap_open_dummy(linktype, snaplen);
}

void pcap_close(pcap_t *p) {
    free(p);
}

int pcap_snapshot(pcap_t *p) {
    if (!p->activated)
        return PCAP_ERROR_NOT_ACTIVATED;
    return p->snapshot;
}

int pcap_datalink(pcap_t *p) {
    return p->linktype;
}

// so we don't need to compile pcap.c
int pcapint_strcasecmp(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        int d = (unsigned char)tolower((unsigned char)*s1) -
                (unsigned char)tolower((unsigned char)*s2);
        if (d != 0) return d;
        s1++; s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}


// see pcap nametoaddr.c
int ether_hostton(const char *name, struct { unsigned char ether_addr_octet[6]; } *addr) {
    return _env_ether_hostton(name, addr->ether_addr_octet) != 0 ? -1 : 0;
}

// not used with HAVE_ETHER_HOSTTON, but gencode.c still references it
struct pcap_etherent *pcap_next_etherent(unused FILE *fp) { return NULL; }

// stubs for pcap error message formatting, returning NULL is okay
const char *pcap_datalink_val_to_name(unused int dlt) { return NULL; }
const char *pcap_datalink_val_to_description(unused int dlt) { return NULL; }
const char *pcap_datalink_val_to_description_or_dlt(int dlt) {
    static char buf[16];
    snprintf(buf, sizeof(buf), "DLT %d", dlt);
    return buf;
}
const char *pcap_strerror(unused int errnum) {
    return "error";
}

const char *_pcap_errbuf(pcap_t *pcap) {
    return pcap->errbuf;
}
