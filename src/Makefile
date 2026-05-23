MAKEFLAGS += -r

WASM2GO_VERSION := v0.4.6

CC       := wasm32-wasip1-clang
GO       := $(if $(GOROOT),$(GOROOT)/bin/,)go
LEX      := flex
YACC     := bison
WASM_OPT := wasm-opt
WASM2GO  := $(GO) run github.com/ncruces/wasm2go@$(WASM2GO_VERSION)
LIBC_GEN := $(GO) run github.com/ncruces/wasm2go/libc-gen@$(WASM2GO_VERSION)

OUTDIR := ../internal/

CFLAGS := \
	-isystemlibc \
	-isystem. \
	-Ilibpcap \
	-ffreestanding \
	-nostdlib \
	-mmutable-globals \
	-mbulk-memory \
	-mmultivalue \
	-Xclang -target-abi -Xclang experimental-mv \
	-mnontrapping-fptoint \
	-msign-ext \
	-O2 \
	-Wall \
	-Wno-unused-function \
	-Wno-deprecated-declarations

LDFLAGS := \
	-mexec-model=reactor \
	-nostdlib \
	-Wl,--export=bpf_compile \
	-Wl,--export=bpf_result_free \
	-Wl,--export=bpf_errbuf \
	-Wl,--export=bpf_filter \
	-Wl,--export=bpf_image \
	-Wl,--export=malloc \
	-Wl,--export=free \
	-Wl,--export=__stack_pointer \
	-Wl,--import-undefined \
	-Wl,--no-entry \
	-Wl,--strip-debug

SRCS := \
	libc/libc.c \
	libc/malloc_bump.c \
	libpcap/gencode.c \
	libpcap/optimize.c \
	libpcap/nametoaddr.c \
	libpcap/bpf_filter.c \
	libpcap/bpf_image.c \
	libpcap/fmtutils.c \
	grammar.c \
	scanner.c \
	netdb.c \
	netinet.c \
	pcap-dummy.c \
	bpf.c

OBJS := \
	$(patsubst libpcap/%.c,%.o,$(filter libpcap/%,$(SRCS))) \
	$(patsubst libc/%.c,%.o,$(filter libc/%,$(SRCS))) \
	$(patsubst %.c,%.o,$(filter-out libpcap/% libc/%,$(SRCS)))

.PHONY: all clean distclean download

all: $(OUTDIR)LICENSE $(OUTDIR)bpf.go $(OUTDIR)libc.go $(OUTDIR)const.go

clean:
	rm -f *.o *.wasm *.opt.wasm *.txt grammar.* scanner.*
	rm -rf libc

distclean: clean
	rm -rf libpcap

download:
	CGO_ENABLED=0 $(GO) run ./download.go

$(OUTDIR)bpf.go: bpf.opt.wasm $(OUTDIR)libc.go
	CGO_ENABLED=0 $(WASM2GO) -embed -provided $(OUTDIR)libc.go -o $@ $<
	sed -i 's/^package .*/package bpf_wasm/' $@

$(OUTDIR)libc.go: bpf.opt.wasm
	CGO_ENABLED=0 $(LIBC_GEN) -wasm $< -pkg bpf_wasm -o $@

$(OUTDIR)const.go: pcap.txt dlt.txt
	CGO_ENABLED=0 $(GO) run ./constgen.go -o $@ $^

$(OUTDIR)LICENSE: libpcap/LICENSE
	install -m644 $< $@

# look for c files in libc and libpcap too
vpath %.c libc libpcap

# everything depends on our headers
$(OBJS): $(wildcard *.h)

# everything depends on the generated grammar
$(OBJS): scanner.h grammar.h

# generate wasm2go libc (and remove some conflicting headers)
libc/.generated:
	CGO_ENABLED=0 $(LIBC_GEN) -c-out libc
	rm -f libc/setjmp.h
	rm -rf libc/sys
	touch $@

# declare libc sources as explicit targets so make can match the pattern rule
# for libc.o/malloc_bump.o even before libc/ is generated
libc/libc.c libc/malloc_bump.c: libc/.generated ;

# some libc patches
libc.o: CFLAGS += -DSTB_SPRINTF_IMPLEMENTATION -DSTB_SPRINTF_NOFLOAT -include libc/stb_sprintf.h
malloc_bump.o: CFLAGS += -Wno-c23-extensions
scanner.o: CFLAGS += -include scanner_compat.h

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

bpf.opt.wasm: bpf.wasm
	$(WASM_OPT) $< -o $@ -O3 --enable-multivalue --low-memory-unused --gufa --converge

grammar.c grammar.h: grammar.y
	$(YACC) -p pcap_ -o grammar.c -d grammar.y

grammar.y: libpcap/grammar.y.in
	sed 's/@REENTRANT_PARSER@/%define api.pure/' $< > $@

scanner.c scanner.h: libpcap/scanner.l grammar.h
	$(LEX) -P pcap_ --header-file=scanner.h --nounput -o scanner.c $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
