// Command pcap-compile-filter compiles a tcpdump-style filter to BPF.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/pgaskin/go-pcapfilter"
)

var (
	raw        = flag.Bool("r", false, "output raw bytes instead of disassembly")
	optimize   = flag.Bool("o", false, "optimize the filter")
	dltName    = flag.String("t", "EN10MB", "link-layer type name (e.g. EN10MB, DLT_LINUX_SLL) or numeric value")
	snaplen    = flag.Int("s", 65535, "snapshot length")
	resolver   = flag.String("d", "", `DNS resolver (host:port) or "auto" for the system resolver`)
	ethersPath = flag.String("e", "", "path to ethers file for hardware address lookup")
	netmask    = flag.String("n", "", "ipv4 netmask of the local network, if known (cidr, addr, or prefix length)")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s filter...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	var linkType pcapfilter.LinkType
	if err := linkType.UnmarshalText([]byte(*dltName)); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid link type %q\n", *dltName)
		os.Exit(2)
	}

	ethers, err := loadEthers(*ethersPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load ethers %q: %v\n", *ethersPath, err)
		os.Exit(2)
	}

	nm, err := parseMask(*netmask)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid netmask %q: %v\n", *netmask, err)
		os.Exit(2)
	}

	p, err := pcapfilter.Compile(strings.Join(flag.Args(), " "), &pcapfilter.Options{
		LinkType: linkType,
		Snaplen:  *snaplen,
		Lookup:   newLookup(*resolver),
		Ethers:   ethers,
		Optimize: *optimize,
		Netmask:  nm,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: compile filter: %v\n", err)
		os.Exit(1)
	}

	if *raw {
		_, err = os.Stdout.Write(p.Bytes())
	} else {
		_, err = os.Stdout.WriteString(p.String() + "\n")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: write bpf: %v\n", err)
		os.Exit(1)
	}
}

func parseMask(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	bitsToMask := func(bits int) netip.Addr {
		mask := ^uint32(0) << (32 - bits)
		return netip.AddrFrom4([4]byte{byte(mask >> 24), byte(mask >> 16), byte(mask >> 8), byte(mask)})
	}
	if prefix, err := netip.ParsePrefix(s); err == nil {
		if !prefix.Addr().Is4() {
			return netip.Addr{}, fmt.Errorf("not ipv4")
		}
		return bitsToMask(prefix.Bits()), nil
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		if !addr.Is4() {
			return netip.Addr{}, fmt.Errorf("not ipv4")
		}
		b := addr.As4()
		if inv := ^binary.BigEndian.Uint32(b[:]); inv&(inv+1) != 0 {
			return netip.Addr{}, fmt.Errorf("invalid mask")
		}
		return addr, nil
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 32 {
		return bitsToMask(n), nil
	}
	return netip.Addr{}, fmt.Errorf("not a valid cidr, mask, or prefix length")
}

func newLookup(resolver string) pcapfilter.LookupFunc {
	var r *net.Resolver
	if resolver == "auto" {
		r = net.DefaultResolver
	} else if resolver != "" {
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, "udp", resolver)
			},
		}
	}
	return func(host string) ([]netip.Addr, error) {
		fmt.Println(r.LookupNetIP(context.Background(), "ip", host))
		if r == nil {
			return nil, errors.New("dns resolver not available")
		}
		return r.LookupNetIP(context.Background(), "ip", host)
	}
}

func loadEthers(name string) (pcapfilter.EthersFunc, error) {
	var ethers map[string]net.HardwareAddr
	if name != "" {
		ethers = make(map[string]net.HardwareAddr)

		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			mac, err := net.ParseMAC(f[0])
			if err != nil {
				continue
			}
			ethers[f[1]] = mac
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return func(name string) (net.HardwareAddr, error) {
		if ethers == nil {
			return nil, errors.New("ethers not available")
		}
		mac, ok := ethers[name]
		if !ok {
			return nil, fmt.Errorf("unknown host %q", name)
		}
		return mac, nil
	}, nil
}
