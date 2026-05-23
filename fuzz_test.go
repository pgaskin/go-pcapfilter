package pcapfilter

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"
)

func FuzzCompile(f *testing.F) {
	keywords, err := loadScannerKeywords("src/libpcap/scanner.l")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			f.Skip("libpcap source not available (run go -C src run download.go)")
		} else {
			f.Errorf("load keywords: %v", err)
		}
		return
	}

	//ff, _ := os.Create(filepath.Join(os.TempDir(), "fuzz.txt"))
	//fmt.Fprintf(ff, "%q\n", keywords)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		expr := mkexpr(keywords, data)
		if expr == "" {
			return
		}

		p, err := Compile(expr, nil)
		//fmt.Fprintf(ff, "%q %v\n", expr, err)
		if err != nil {
			return
		}

		_ = p.Instructions()
		_ = p.String()
		_ = p.Match(data) // match it on itself lol
	})
}

// fuzzExpr generates mostly well-formed expressions. It is not comprehensive.
type fuzzExpr struct {
	keywords []string
	data     []byte
	pos      int
}

// loadScannerKeywords extracts literal keyword strings from lines like
// `word[|word...]   return TOKEN;` in scanner.l.
func loadScannerKeywords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		keywords []string
		inRules  bool
		scanner  = bufio.NewScanner(f)
		re       = regexp.MustCompile(`^([\w|.\-]+)\s+return\s+\w`)
	)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "%%" {
			inRules = !inRules
			continue
		}
		if !inRules {
			continue
		}
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		for alt := range strings.SplitSeq(m[1], "|") {
			if alt != "" {
				keywords = append(keywords, alt)
			}
		}
	}
	if len(keywords) == 0 {
		return nil, fmt.Errorf("no keywords found")
	}
	return keywords, scanner.Err()
}

func mkexpr(keywords []string, data []byte) string {
	r := &fuzzExpr{
		keywords: keywords,
		data:     data,
	}
	return r.expr(3)
}

func (r *fuzzExpr) next() (uint8, bool) {
	if r.pos >= len(r.data) {
		return 0, false
	}
	v := r.data[r.pos]
	r.pos++
	return v, true
}

func (r *fuzzExpr) expr(depth int) string {
	b, ok := r.next()
	if !ok {
		return r.leaf()
	}
	if depth > 0 {
		switch int(b) % 16 {
		case 1: // not (expr)
			if inner := r.expr(depth - 1); inner != "" {
				return "not (" + inner + ")"
			}
		case 2, 3: // (expr) and/or (expr)
			ops := []string{"and", "or"}
			op := ops[int(b)%len(ops)]
			left := r.expr(depth - 1)
			right := r.expr(depth - 1)
			switch {
			case left != "" && right != "":
				return "(" + left + ") " + op + " (" + right + ")"
			case left != "":
				return left
			case right != "":
				return right
			}
		}
	}
	return r.leaf()
}

func (r *fuzzExpr) leaf() string {
	ctrl, ok := r.next()
	if !ok || len(r.keywords) == 0 {
		return ""
	}

	// case 5 (1/8 chance): arithmetic comparison, no keyword or direction
	if ctrl&0x7 == 5 {
		return r.arith()
	}

	b, _ := r.next()
	kw := r.keywords[int(b)%len(r.keywords)]
	a, _ := r.next()
	b2, _ := r.next()

	// bits 0-2: argument type
	var arg string
	switch ctrl & 0x7 {
	case 0: // bare keyword, no argument
	case 1: // number
		arg = fmt.Sprintf(" %d", int(a)<<8|int(b2))
	case 2: // IPv4
		c, _ := r.next()
		d, _ := r.next()
		arg = " " + netip.AddrFrom4([4]byte{a, b2, c, d}).String()
	case 3: // portrange lo-hi
		c, _ := r.next()
		d, _ := r.next()
		lo, hi := int(a)<<8|int(b2), int(c)<<8|int(d)
		if lo > hi {
			lo, hi = hi, lo
		}
		arg = fmt.Sprintf(" %d-%d", lo, hi)
	case 4: // IPv6
		var b16 [16]byte
		b16[0], b16[1] = a, b2
		for i := 2; i < 16; i++ {
			b16[i], _ = r.next()
		}
		arg = " " + netip.AddrFrom16(b16).String()
	default: // number (cases 6-7)
		arg = fmt.Sprintf(" %d", int(a)<<8|int(b2))
	}

	// bits 3-4: optional direction qualifier
	dirs := []string{"", "src ", "dst ", "src or dst "}
	dir := dirs[(ctrl>>3)&0x3]

	return dir + kw + arg
}

var arithProtos = []string{"ip", "ip6", "tcp", "udp", "icmp", "ether", "arp", "icmp6"}

func (r *fuzzExpr) arith() string {
	left := r.arithTerm()
	b, _ := r.next()
	relops := []string{" > ", " < ", " >= ", " <= ", " = ", " != "}
	relop := relops[int(b)%len(relops)]
	right := r.arithTerm()
	return left + relop + right
}

func (r *fuzzExpr) arithTerm() string {
	b, ok := r.next()
	if !ok {
		return "0"
	}
	switch int(b) % 4 {
	case 0:
		return "len"
	case 1:
		a, _ := r.next()
		b2, _ := r.next()
		return fmt.Sprintf("%d", int(a)<<8|int(b2))
	case 2: // proto[offset]
		proto := arithProtos[int(b)%len(arithProtos)]
		off, _ := r.next()
		return fmt.Sprintf("%s[%d]", proto, off)
	default: // proto[offset:width]
		proto := arithProtos[int(b)%len(arithProtos)]
		off, _ := r.next()
		wb, _ := r.next()
		widths := []int{1, 2, 4}
		return fmt.Sprintf("%s[%d:%d]", proto, off, widths[int(wb)%3])
	}
}
