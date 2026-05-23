MAKEFLAGS += -r

CC      := wasm32-wasip1-clang
GO      := $(if $(GOROOT),$(GOROOT)/bin/,)go
LEX     := flex
YACC    := bison
WASM2GO := $(GO) run github.com/ncruces/wasm2go@v0.4.6

OUTDIR := ../internal/

CFLAGS := \
	-isystem. \
	-Ilibpcap \
	-O2 \
	-Wall \
	-Wno-unused-function \
	-Wno-deprecated-declarations

LDFLAGS := \
	-mexec-model=reactor \
	-Wl,--export=bpf_compile \
	-Wl,--export=bpf_result_count \
	-Wl,--export=bpf_result_insns \
	-Wl,--export=bpf_result_free \
	-Wl,--export=bpf_errbuf \
	-Wl,--export=malloc \
	-Wl,--export=free \
	-Wl,--export=__stack_pointer \
	-Wl,--allow-undefined \
	-Wl,--strip-debug

SRCS := \
	libpcap/gencode.c \
	libpcap/optimize.c \
	libpcap/nametoaddr.c \
	libpcap/bpf_filter.c \
	libpcap/fmtutils.c \
	grammar.c \
	scanner.c \
	netdb.c \
	pcap-dummy.c \
	bpf.c

OBJS := \
	$(patsubst libpcap/%.c,%.o,$(filter libpcap/%,$(SRCS))) \
	$(patsubst %.c,%.o,$(filter-out libpcap/%,$(SRCS)))

.PHONY: all clean distclean download

all: $(OUTDIR)LICENSE $(OUTDIR)bpf.go $(OUTDIR)const.go

clean:
	rm -fv *.o *.wasm *.txt grammar.* scanner.*

distclean: clean
	rm -rf libpcap

download:
	CGO_ENABLED=0 $(GO) run ./download.go

$(OUTDIR)bpf.go: bpf.wasm
	CGO_ENABLED=0 $(WASM2GO) -o $@ $<

$(OUTDIR)const.go: pcap.txt dlt.txt
	CGO_ENABLED=0 $(GO) run ./constgen.go -o $@ $^

$(OUTDIR)LICENSE: libpcap/LICENSE
	install -m644 $< $@

# everything depends on our headers
$(OBJS): $(wildcard *.h)

# everything depends on the generated grammar
$(OBJS): scanner.h grammar.h

# preprocess dlt.h to handle conditions, then extract defines
dlt.txt: libpcap/pcap/dlt.h
	$(CC) -E -dM $< \
		| grep -E '^#define DLT_[A-Z0-9_]+ [0-9]+$$' \
		| grep -v MATCHING \
		| sort -k3 -n \
		> $@

# some constants from pcap.h
pcap.txt: libpcap/pcap/pcap.h
	grep -E '^#define' $< \
		| grep -Fe 'PCAP_NETMASK_UNKNOWN' \
		| sort -k3 -n \
		> $@

bpf.wasm: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

grammar.c grammar.h: grammar.y
	$(YACC) -p pcap_ -o grammar.c -d grammar.y

grammar.y: libpcap/grammar.y.in
	sed 's/@REENTRANT_PARSER@/%define api.pure/' $< > $@

scanner.c scanner.h: libpcap/scanner.l grammar.h
	$(LEX) -P pcap_ --header-file=scanner.h --nounput -o scanner.c $<

%.o: libpcap/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
