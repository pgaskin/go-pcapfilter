//go:build ignore

package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	Repo   = "the-tcpdump-group/libpcap"
	Commit = "6b5de1e5f07a4fea6672caa2d34935c3da24a8f2"
	Dest   = "libpcap"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: download libpcap: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	resp, err := http.Get("https://github.com/" + Repo + "/archive/" + url.PathEscape(Commit) + ".tar.gz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response status %d", resp.StatusCode)
	}

	if err := os.RemoveAll(Dest); err != nil {
		return fmt.Errorf("remove %s: %w", Dest, err)
	}

	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}

	tr := tar.NewReader(zr)
	var pfx string
	for {
		f, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}

		if f.Name == "pax_global_header" || f.FileInfo().IsDir() {
			continue
		}

		if pfx == "" {
			rest := strings.TrimPrefix(f.Name, "./")
			_, rest, _ = strings.Cut(rest, "/")
			if rest == "" {
				continue
			}
			pfx = f.Name[:len(f.Name)-len(rest)]
		}

		name, ok := strings.CutPrefix(f.Name, pfx)
		if !ok {
			return fmt.Errorf("unexpected path %q (prefix %q)", f.Name, pfx)
		}

		dst := filepath.Join(Dest, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0777); err != nil {
			return err
		}
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		out.Close()
		if err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
	}
	if err := os.WriteFile(filepath.Join(Dest, "COMMIT"), []byte(Commit), 0666); err != nil {
		return fmt.Errorf("write commit: %w", err)
	}
	return nil
}
