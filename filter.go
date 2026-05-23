package pcapfilter

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	bpf_wasm "github.com/pgaskin/go-pcapfilter/internal"
)

//go:generate docker build --platform amd64 --progress plain --output . src
//go:generate go run dlt.go

// LinkType is an opaque DLT_ link-layer type constant. Use the DLT_*
// constants defined in this package rather than raw integers.
type LinkType int

// Program is a compiled filter. It is safe for concurrent use, but contains a
// mutex.
type Program struct {
	mu      sync.Mutex
	env     *env
	n       int32
	ptr     int32
	pkt     int32
	snaplen int32
}

// RawInstruction is a raw BPF virtual machine instruction.
//
// This is the same as golang.org/x/net/bpf.RawInstruction, and can be cast
// directly to it.
type RawInstruction struct {
	// Operation to execute.
	Op uint16
	// For conditional jump instructions, the number of instructions
	// to skip if the condition is true/false.
	Jt uint8
	Jf uint8
	// Constant parameter. The meaning depends on the Op.
	K uint32
}

// Options contains compilation options for a filter expression.
type Options struct {
	// LinkType identifies the kind of packet the filter will be used for, which
	// affects the offsets and the valid expressions. If zero, [DLT_EN10MB] is
	// used, which is suitable for ethernet packet captures.
	LinkType LinkType

	// Snaplen is the maximum number of bytes to look at in each packet. If nil,
	// 65535 is used.
	Snaplen int

	// Netmask, is the IPv4 netmask of the local network, used by "broadcast" in
	// expressions. If zero, broadcast checks are skipped.
	Netmask netip.Addr

	// Optimize enables the BPF optimizer.
	Optimize bool

	// Lookup is the lookup function to use for host ip addresses. If nil,
	// address lookup is disabled.
	Lookup LookupFunc

	// Ethers is the lookup function to use for hardware addresses. If nil,
	// hardware address lookup is disabled.
	Ethers EthersFunc
}

// LookupFunc resolves hostnames for "host name" expressions. It should return
// all IPv4 and IPv6 addresses for the specified hostname. The first address
// matching the family will be used.
type LookupFunc func(name string) ([]netip.Addr, error)

// EthersFunc looks up MAC addresses for "ether host name" expressions.
type EthersFunc func(name string) (net.HardwareAddr, error)

var (
	DefaultLinkType = DLT_EN10MB
	DefaultSnaplen  = 65535
)

// LookupDefaultResolver looks up a host using [net.DefaultResolver].
func LookupDefaultResolver(host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
}

// Compile compiles a tcpdump filter expression to a BPF program.
func Compile(filter string, opts *Options) (p *Program, err error) {
	if opts == nil {
		opts = new(Options)
	}
	env := &env{
		lookup: opts.Lookup,
		ethers: opts.Ethers,
	}
	mod := bpf_wasm.New(env)

	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(panicErr); ok {
				// pcap sets errbuf before calling longjmp.
				msg := env.cstr(uint32(mod.Xbpf_errbuf()))
				if msg == "" {
					msg = r.(panicErr).msg
				}
				err = errors.New(msg)
			} else {
				panic(r)
			}
		}
	}()

	ptr, free, err := env.mkcstr(filter)
	if err != nil {
		return nil, err
	}
	defer free()

	linkType := int32(DefaultLinkType)
	if opts.LinkType != 0 {
		linkType = int32(opts.LinkType)
	}

	snaplen := int32(DefaultSnaplen)
	if opts.Snaplen != 0 {
		snaplen = int32(opts.Snaplen)
	}

	optimize := int32(0)
	if opts.Optimize {
		optimize = 1
	}

	netmask := uint32(bpf_wasm.PCAP_NETMASK_UNKNOWN)
	if opts.Netmask.IsValid() && opts.Netmask.Is4() {
		b := opts.Netmask.As4()
		netmask = binary.BigEndian.Uint32(b[:])
	}

	n, ptr := mod.Xbpf_compile(linkType, snaplen, ptr, optimize, int32(netmask))
	if n < 0 {
		msg := env.cstr(uint32(mod.Xbpf_errbuf()))
		return nil, errors.New(msg)
	}
	// don't bpf_result_free it

	pkt := mod.Xmalloc(snaplen)
	if pkt == 0 {
		return nil, errors.New("out of wasm memory")
	}

	return &Program{
		env:     env,
		n:       n,
		ptr:     ptr,
		pkt:     pkt,
		snaplen: snaplen,
	}, nil
}

// MarshalBinary returns the raw BPF instructions for the filter.
func (p *Program) MarshalBinary() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Clone((*p.env.mod.Xmemory().Slice())[p.ptr : p.ptr+p.n*8]), nil
}

// Instructions returns the raw BPF instructions for the filter.
func (p *Program) Instructions() []RawInstruction {
	p.mu.Lock()
	defer p.mu.Unlock()

	raw := make([]RawInstruction, p.n)
	buf := *p.env.mod.Xmemory().Slice()
	for i := range p.n {
		tmp := buf[p.ptr+i*8:]
		raw[i] = RawInstruction{
			Op: binary.LittleEndian.Uint16(tmp),
			Jt: tmp[2],
			Jf: tmp[3],
			K:  binary.LittleEndian.Uint32(tmp[4:]),
		}
	}
	return raw
}

// String returns a multi-line disassembly of the program.
func (p *Program) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	var b strings.Builder
	for i := range p.n {
		if i > 0 {
			b.WriteByte('\n')
		}
		// bpf_image doesn't allocate memory (it uses a static buffer)
		b.WriteString(p.env.cstr(uint32(p.env.mod.Xbpf_image(p.ptr+i*8, i))))
	}
	return b.String()
}

// Match returns true if pkt matches the compiled filter.
func (p *Program) Match(pkt []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	n := copy((*p.env.mod.Xmemory().Slice())[p.pkt:], pkt[:min(len(pkt), int(p.snaplen))])
	return p.env.mod.Xbpf_filter(p.ptr, p.pkt, int32(len(pkt)), int32(n)) != 0
}

type panicErr struct{ msg string }

func (e panicErr) Error() string { return e.msg }

type env struct {
	mod    *bpf_wasm.Module
	lookup func(host string) ([]netip.Addr, error)
	ethers func(name string) (net.HardwareAddr, error)
}

func (env *env) Init(m any) {
	env.mod = m.(*bpf_wasm.Module)
}

func (env *env) Xpanic(v0 int32) {
	panic(panicErr{env.cstr(uint32(v0))})
}

func (env *env) Xresolve_host(hostnamePtr, family, outPtr int32) int32 {
	if env.lookup == nil {
		return -1
	}
	addrs, err := env.lookup(env.cstr(uint32(hostnamePtr)))
	if err != nil || len(addrs) == 0 {
		return -1
	}
	for _, addr := range addrs {
		if family == 4 && addr.Is4() {
			ip4 := addr.As4()
			copy((*env.mod.Xmemory().Slice())[uint32(outPtr):], ip4[:])
			return 0
		}
		if family == 6 && addr.Is6() {
			ip6 := addr.As16()
			copy((*env.mod.Xmemory().Slice())[uint32(outPtr):], ip6[:])
			return 0
		}
	}
	return -1
}

func (env *env) Xether_hostton(namePtr, outPtr int32) int32 {
	if env.ethers == nil {
		return -1
	}
	mac, err := env.ethers(env.cstr(uint32(namePtr)))
	if err != nil || len(mac) != 6 {
		return -1
	}
	copy((*env.mod.Xmemory().Slice())[uint32(outPtr):], mac)
	return 0
}

func (env *env) mkcstr(s string) (int32, func(), error) {
	b := []byte(s)
	ptr := env.mod.Xmalloc(int32(len(b) + 1))
	if ptr == 0 {
		return 0, nil, errors.New("out of wasm memory")
	}
	mem := *env.mod.Xmemory().Slice()
	copy(mem[uint32(ptr):], b)
	mem[uint32(ptr)+uint32(len(b))] = 0
	return ptr, func() { env.mod.Xfree(ptr) }, nil
}

func (env *env) cstr(ptr uint32) string {
	buf := *env.mod.Xmemory().Slice()
	end := ptr
	for end < uint32(len(buf)) && buf[end] != 0 {
		end++
	}
	return string(buf[ptr:end])
}
