package main

import (
	"net/netip"
	"runtime/debug"

	"github.com/pgaskin/go-pcapfilter"
)

func main() {
	raw, err := pcapfilter.Compile("tcp port 443 and host test", &pcapfilter.Options{
		Lookup: func(name string) ([]netip.Addr, error) {
			if name == "test" {
				debug.PrintStack()
			}
			return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
		},
	})
	if err != nil {
		panic(err)
	}
	_ = raw
}
