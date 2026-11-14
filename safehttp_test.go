package main

import (
	"strings"
	"testing"
)

func TestValidateFetchURLRejectsUnsafe(t *testing.T) {
	opt := defaultSafeHTTPOptions()
	cases := []string{
		"",
		"http://example.com/a",
		"file:///etc/passwd",
		"https://user:pass@example.com/a",
		"https://127.0.0.1/a",
		"https://10.0.0.5/a",
		"https://192.168.1.2/a",
		"https://169.254.1.1/a",
		"https://[::1]/a",
		"https://localhost/a",
		"https://printer.local/a",
		"https://example.com/../secret",
	}
	for _, raw := range cases {
		if _, err := validateFetchURL(raw, opt); err == nil {
			t.Fatalf("expected reject: %s", raw)
		}
	}
}

func TestValidateFetchURLAcceptsPublicHTTPS(t *testing.T) {
	opt := defaultSafeHTTPOptions()
	u, err := validateFetchURL("https://piston-data.mojang.com/v1/objects/abc", opt)
	if err != nil || u == nil {
		t.Fatalf("expected accept, got %v", err)
	}
	opt.AllowHosts = []string{"mojang.com", "*.bangbang93.com"}
	if _, err := validateFetchURL("https://launcher.mojang.com/a", opt); err != nil {
		t.Fatalf("mojang should pass: %v", err)
	}
	if _, err := validateFetchURL("https://bmclapi2.bangbang93.com/a", opt); err != nil {
		t.Fatalf("wildcard should pass: %v", err)
	}
	if _, err := validateFetchURL("https://evil.example.org/a", opt); err == nil {
		t.Fatal("host outside allow list must be rejected")
	}
}

func TestHostAllowed(t *testing.T) {
	if !hostAllowed("any.example.com", nil) {
		t.Fatal("empty allow list means unrestricted")
	}
	if hostAllowed("evil.com", []string{"mojang.com"}) {
		t.Fatal("substring match must not pass")
	}
	if !hostAllowed("a.mojang.com", []string{"mojang.com"}) {
		t.Fatal("subdomain of allowed host should pass")
	}
	if hostAllowed("bangbang93.com.evil.io", []string{"*.bangbang93.com"}) {
		t.Fatal("wildcard suffix must be anchored")
	}
}

func TestReadBounded(t *testing.T) {
	data, err := readBounded(strings.NewReader("0123456789"), 10)
	if err != nil || len(data) != 10 {
		t.Fatalf("exact limit should pass: %v", err)
	}
	if _, err := readBounded(strings.NewReader("0123456789A"), 10); err == nil {
		t.Fatal("over limit must fail")
	}
}
