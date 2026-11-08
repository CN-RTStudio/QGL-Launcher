package main

import (
	"strings"
	"testing"
)

func TestFavicon_DataURI(t *testing.T) {
	// 1x1 透明 PNG 标准 base64。
	png := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	field := "data:image/png;base64," + png
	out, err := ValidateServerFavicon(field)
	if err != nil {
		t.Fatalf("should accept data uri: %v", err)
	}
	if out != png {
		t.Fatalf("unexpected cleaned payload")
	}
}

func TestFavicon_NonDataURI(t *testing.T) {
	if _, err := ValidateServerFavicon("https://evil.example/icon.png"); err == nil {
		t.Fatal("remote URL favicon must be rejected")
	}
}

func TestFavicon_BadBase64(t *testing.T) {
	if _, err := ValidateServerFavicon("data:image/png;base64,!!!notbase64!!!"); err == nil {
		t.Fatal("bad base64 must fail")
	}
}

func TestFavicon_Empty(t *testing.T) {
	out, err := ValidateServerFavicon("")
	if err != nil || out != "" {
		t.Fatalf("empty should pass with empty out, got %q %v", out, err)
	}
}

func TestFaviconURL_OK(t *testing.T) {
	if err := ValidateServerFaviconURL("https://cdn.example.com/icon.png"); err != nil {
		t.Fatalf("public https should pass: %v", err)
	}
}

func TestFaviconURL_HttpRejected(t *testing.T) {
	if err := ValidateServerFaviconURL("http://cdn.example.com/icon.png"); err == nil {
		t.Fatal("http must be rejected")
	}
}

func TestFaviconURL_PrivateHost(t *testing.T) {
	for _, h := range []string{"http://127.0.0.1/i.png", "https://192.168.1.1/i.png"} {
		_ = strings.TrimSpace(h)
	}
	if err := ValidateServerFaviconURL("https://127.0.0.1/i.png"); err == nil {
		t.Fatal("loopback must be rejected")
	}
	if err := ValidateServerFaviconURL("https://10.0.0.5/i.png"); err == nil {
		t.Fatal("private must be rejected")
	}
}

func TestFavicon_OversizedPayloadRejectedBeforeDecode(t *testing.T) {
	huge := strings.Repeat("A", maxServerFaviconEncoded+8)
	if _, err := ValidateServerFavicon("data:image/png;base64," + huge); err == nil {
		t.Fatal("oversized payload must be rejected without decoding")
	}
}

func TestFavicon_ReturnsCanonicalBase64(t *testing.T) {
	png := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	out, err := ValidateServerFavicon("data:image/png;base64,  " + png + "  ")
	if err != nil {
		t.Fatalf("padded payload should decode: %v", err)
	}
	if out != png {
		t.Fatalf("payload must be re-encoded canonically")
	}
}

func TestFaviconURL_HostOnly(t *testing.T) {
	if h, ok := faviconHostOnly("  CDN.Example.COM.  "); !ok || h != "cdn.example.com" {
		t.Fatalf("normalisation failed: %q %v", h, ok)
	}
	for _, h := range []string{"", "localhost", "a", "1.2.3.4", "::1", "x.y.123", "a..b", "a b", "a%b.c", "a/b.c", "user@host.example"} {
		if _, ok := faviconHostOnly(h); ok {
			t.Fatalf("%q must be rejected", h)
		}
	}
}

func TestFaviconURL_StructuralChecks(t *testing.T) {
	cases := []string{
		"https://user:pass@cdn.example.com/i.png",
		"https://cdn.example.com@evil.example/i.png",
		"https:\\\\127.0.0.1\\i.png",
		"https://localhost/i.png",
		"https://localhost./i.png",
		"https://192.168.0.1/i.png",
		"https://[::1]/i.png",
		"https://2130706433/i.png",
		"https://intranet/i.png",
	}
	for _, u := range cases {
		if err := ValidateServerFaviconURL(u); err == nil {
			t.Fatalf("%s must be rejected", u)
		}
	}
	for _, u := range []string{
		"https://cdn.example.com/i.png",
		"https://CDN.Example.COM./i.png",
		"https://cdn.example.com:8443/i.png",
	} {
		if err := ValidateServerFaviconURL(u); err != nil {
			t.Fatalf("%s should pass: %v", u, err)
		}
	}
}
