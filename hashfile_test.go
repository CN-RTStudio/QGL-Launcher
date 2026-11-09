package main

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"
)

func TestHashFileHexMatchesStdlibVectors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		algo crypto.Hash
		want string
	}{
		{crypto.SHA1, "a9993e364706816aba3e25717850c26c9cd0d89d"},
		{crypto.SHA256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{crypto.SHA512, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
	}
	for _, tc := range cases {
		got, err := hashFileHex(tc.algo, path)
		if err != nil {
			t.Fatalf("%v: %v", tc.algo, err)
		}
		if got != tc.want {
			t.Fatalf("%v digest mismatch: got %s want %s", tc.algo, got, tc.want)
		}
	}
}

func TestHashFileHexReportsMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.bin")
	if _, err := hashFileHex(crypto.SHA1, missing); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestHashFileHexCoversLiteralVerbWrappers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "literal.bin")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrappers := map[string]func(string) (string, error){
		"sha1":   sha1File,
		"sha512": sha512File,
	}
	for name, fn := range wrappers {
		got, err := fn(path)
		if err != nil || got == "" {
			t.Fatalf("%s wrapper failed: %v", name, err)
		}
	}
}
