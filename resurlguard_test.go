package main

import (
	"testing"
)

func TestClassifyResPack_Allowed(t *testing.T) {
	d := classifyResPackURL("https://packs.example.com/rp.zip")
	if !d.Allow {
		t.Fatalf("should allow https host: %+v", d)
	}
}

func TestClassifyResPack_HttpRejected(t *testing.T) {
	d := classifyResPackURL("http://packs.example.com/rp.zip")
	if d.Allow {
		t.Fatal("http must be rejected")
	}
}

func TestClassifyResPack_UserInfoRejected(t *testing.T) {
	d := classifyResPackURL("https://user:pass@packs.example.com/rp.zip")
	if d.Allow {
		t.Fatal("userinfo must be rejected")
	}
}

func TestClassifyResPack_IPLiteralRejected(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "169.254.169.254"} {
		d := classifyResPackURL("https://" + h + "/rp.zip")
		if d.Allow {
			t.Fatalf("ip %s must be rejected: %+v", h, d)
		}
	}
}

func TestClassifyResPack_Garbage(t *testing.T) {
	if d := classifyResPackURL(""); d.Allow {
		t.Fatal("empty rejected")
	}
	if d := classifyResPackURL("ftp://x/y"); d.Allow {
		t.Fatal("ftp rejected")
	}
	if d := classifyResPackURL("://bad"); d.Allow {
		t.Fatal("parse error rejected")
	}
}

func TestAllowResPackBool(t *testing.T) {
	if !allowResPackDownload("https://a.com/r.zip") {
		t.Fatal("bool entry should allow clean https")
	}
	if allowResPackDownload("http://a.com/r.zip") {
		t.Fatal("bool entry must reject http")
	}
}

func TestClassifyResPack_LoopbackVariantsRejected(t *testing.T) {
	cases := []string{
		"https://127.0.0.1/rp.zip",
		"https://127.0.0.1./rp.zip",
		"https://localhost/rp.zip",
		"https://LOCALHOST./rp.zip",
		"https://foo.localhost/rp.zip",
		"https://2130706433/rp.zip",
		"https://0x7f000001/rp.zip",
		"https://[::1]/rp.zip",
		"https://[::1]:8443/rp.zip",
		"https://intranet/rp.zip",
	}
	for _, u := range cases {
		d := classifyResPackURL(u)
		if d.Allow {
			t.Fatalf("%s must be rejected: %+v", u, d)
		}
	}
}

func TestClassifyResPack_OpaqueAndControlChars(t *testing.T) {
	cases := []string{
		"https:\\\\127.0.0.1\\rp.zip",
		"https://packs.example.com/rp.zip\nHost: evil",
		"https://packs.example.com\r/tab\t",
	}
	for _, u := range cases {
		d := classifyResPackURL(u)
		if d.Allow {
			t.Fatalf("%q must be rejected: %+v", u, d)
		}
	}
}

func TestClassifyResPack_AcceptsPublicHosts(t *testing.T) {
	for _, u := range []string{
		"https://packs.example.com/rp.zip",
		"https://RP.Example.COM:8443/rp.zip",
		"https://cdn.example.co.uk/a/b/rp.zip",
	} {
		d := classifyResPackURL(u)
		if !d.Allow {
			t.Fatalf("%s should be allowed: %+v", u, d)
		}
	}
}

func TestResPackHostOnly(t *testing.T) {
	if h, ok := resPackHostOnly("  CDN.Example.COM.  "); !ok || h != "cdn.example.com" {
		t.Fatalf("normalisation failed: %q %v", h, ok)
	}
	for _, h := range []string{"", "localhost", "a", "1.2.3.4", "x.y.123", "a..b", "a b", "a%b.c", "a/b.c", "user@host.example"} {
		if _, ok := resPackHostOnly(h); ok {
			t.Fatalf("%q must be rejected", h)
		}
	}
}
