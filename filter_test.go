package pcapfilter

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
)

var (
	ip1 = [4]byte{10, 0, 0, 1}
	ip2 = [4]byte{10, 0, 0, 2}
	ip3 = [4]byte{192, 168, 1, 1}
	ip4 = [4]byte{1, 2, 3, 4}
	hw1 = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	hw2 = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
)

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		filter  string
		match   [][]byte
		nomatch [][]byte
	}{
		{
			name:   "TCPPort",
			filter: "tcp port 80",
			match: [][]byte{
				tcp4(hw1, hw2, ip1, ip2, 54321, 80),
				tcp4(hw1, hw2, ip1, ip2, 80, 54321),
			},
			nomatch: [][]byte{
				tcp4(hw1, hw2, ip1, ip2, 54321, 443),
				udp4(hw1, hw2, ip1, ip2, 54321, 80),
			},
		},
		{
			name:   "UDPPort",
			filter: "udp port 53",
			match: [][]byte{
				udp4(hw1, hw2, ip1, ip2, 12345, 53),
				udp4(hw1, hw2, ip1, ip2, 53, 12345),
			},
			nomatch: [][]byte{
				udp4(hw1, hw2, ip1, ip2, 12345, 80),
				tcp4(hw1, hw2, ip1, ip2, 12345, 53),
			},
		},
		{
			name:   "IPHost",
			filter: "host 10.0.0.1",
			match: [][]byte{
				tcp4(hw1, hw2, ip1, ip2, 1, 2),
				tcp4(hw1, hw2, ip2, ip1, 1, 2),
			},
			nomatch: [][]byte{
				tcp4(hw1, hw2, ip2, ip3, 1, 2),
			},
		},
		{
			name:   "ARP",
			filter: "arp",
			match: [][]byte{
				arp(hw1, hw2, ip1, ip2),
			},
			nomatch: [][]byte{
				tcp4(hw1, hw2, ip1, ip2, 1, 2),
				udp4(hw1, hw2, ip1, ip2, 1, 2),
			},
		},
		{
			name:   "TCPFlags",
			filter: "tcp[tcpflags] & tcp-syn != 0",
			match: [][]byte{
				func() []byte { p := tcp4(hw1, hw2, ip1, ip2, 1234, 80); p[47] = 0x02; return p }(),
			},
			nomatch: [][]byte{
				func() []byte { p := tcp4(hw1, hw2, ip1, ip2, 1234, 80); p[47] = 0x10; return p }(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm := mkfilter(t, tc.filter, nil)
			for _, pkt := range tc.match {
				test(t, vm, pkt, true)
			}
			for _, pkt := range tc.nomatch {
				test(t, vm, pkt, false)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	opts := &Options{
		Lookup: func(host string) ([]netip.Addr, error) {
			if host == "test" {
				return []netip.Addr{netip.AddrFrom4(ip4)}, nil
			}
			return nil, errors.New("no such host")
		},
	}

	vm := mkfilter(t, "host test", opts)
	test(t, vm, tcp4(hw1, hw2, ip4, ip2, 1, 2), true) // src matches
	test(t, vm, tcp4(hw1, hw2, ip2, ip4, 1, 2), true) // dst matches
	test(t, vm, tcp4(hw1, hw2, ip2, ip3, 1, 2), false)

	_, err := Compile("host unknown", opts)
	if err == nil {
		t.Fatal("expected error for unresolvable host")
	}
}

func TestEthers(t *testing.T) {
	opts := &Options{
		Ethers: func(name string) (net.HardwareAddr, error) {
			if name == "test" {
				return hw1, nil
			}
			return nil, errors.New("not found")
		},
	}

	vm := mkfilter(t, "ether host test", opts)

	pkt1 := make([]byte, 14+20)
	copy(pkt1[0:6], hw1)
	binary.BigEndian.PutUint16(pkt1[12:], 0x0800)
	pkt1[14] = 0x45
	test(t, vm, pkt1, true)

	pkt2 := make([]byte, 14+20)
	copy(pkt2[0:6], hw2)
	binary.BigEndian.PutUint16(pkt2[12:], 0x0800)
	pkt2[14] = 0x45
	test(t, vm, pkt2, false)
}

func TestCompileError(t *testing.T) {
	cases := []struct {
		filter  string
		wantErr string
		opts    *Options
	}{
		{"syntax error @@##", "syntax error", nil},
		{"host notahost", "unknown host", &Options{
			Lookup: func(host string) ([]netip.Addr, error) {
				return nil, errors.New("no such host")
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.filter, func(t *testing.T) {
			_, err := Compile(tc.filter, tc.opts)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := err.Error(); !strings.Contains(got, tc.wantErr) {
				t.Errorf("error %q does not contain %q", got, tc.wantErr)
			}
		})
	}
}

func mkfilter(t *testing.T, filter string, opts *Options) *bpf.VM {
	t.Helper()

	p, err := Compile(filter, opts)
	if err != nil {
		t.Fatalf("Compile(%q): %v", filter, err)
	}
	t.Logf("filter %q\n%s", filter, p)

	raw := p.Instructions()

	tmp := make([]bpf.RawInstruction, len(raw))
	for i, inst := range raw {
		tmp[i] = bpf.RawInstruction(inst)
	}

	insts, ok := bpf.Disassemble(tmp)
	if !ok {
		t.Fatalf("Disassemble: failed to decode all instructions")
	}

	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	return vm
}

func test(t *testing.T, vm *bpf.VM, pkt []byte, match bool) {
	t.Helper()
	n, err := vm.Run(pkt)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n != 0 {
		if !match {
			t.Errorf("expected no match, got match (%d)", n)
		}
	} else {
		if match {
			t.Errorf("expected match, got no match (%d)", n)
		}
	}
}

func tcp4(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 14+20+20)
	copy(pkt[0:6], dstMAC)
	copy(pkt[6:12], srcMAC)
	binary.BigEndian.PutUint16(pkt[12:], 0x0800) // ethertype IPv4
	pkt[14] = 0x45                               // version=4, IHL=5
	pkt[22] = 64                                 // TTL
	pkt[23] = 6                                  // protocol TCP
	binary.BigEndian.PutUint16(pkt[16:], 40)     // total length
	copy(pkt[26:30], srcIP[:])
	copy(pkt[30:34], dstIP[:])
	binary.BigEndian.PutUint16(pkt[34:], srcPort)
	binary.BigEndian.PutUint16(pkt[36:], dstPort)
	pkt[46] = 0x50 // offset = 20 bytes
	return pkt
}

func udp4(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 14+20+8)
	copy(pkt[0:6], dstMAC)
	copy(pkt[6:12], srcMAC)
	binary.BigEndian.PutUint16(pkt[12:], 0x0800) // ethertype IPv4
	pkt[14] = 0x45
	pkt[22] = 64
	pkt[23] = 17 // protocol UDP
	binary.BigEndian.PutUint16(pkt[16:], 28)
	copy(pkt[26:30], srcIP[:])
	copy(pkt[30:34], dstIP[:])
	binary.BigEndian.PutUint16(pkt[34:], srcPort)
	binary.BigEndian.PutUint16(pkt[36:], dstPort)
	binary.BigEndian.PutUint16(pkt[38:], 8) // length
	return pkt
}

func arp(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP [4]byte) []byte {
	pkt := make([]byte, 14+28)
	copy(pkt[0:6], dstMAC)
	copy(pkt[6:12], srcMAC)
	binary.BigEndian.PutUint16(pkt[12:], 0x0806) // ethertype ARP
	binary.BigEndian.PutUint16(pkt[14:], 1)      // hardware type Ethernet
	binary.BigEndian.PutUint16(pkt[16:], 0x0800) // protocol IPv4
	pkt[18] = 6                                  // hardware addr len
	pkt[19] = 4                                  // protocol addr len
	binary.BigEndian.PutUint16(pkt[20:], 1)      // op=request
	copy(pkt[22:28], srcMAC)
	copy(pkt[28:32], srcIP[:])
	copy(pkt[38:42], dstIP[:])
	return pkt
}
