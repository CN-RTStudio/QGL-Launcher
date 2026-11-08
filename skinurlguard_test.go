package main

import (
	"testing"
)

func TestClassifySkinURL_OfficialAllowed(t *testing.T) {
	d := classifySkinURL("https://textures.minecraft.net/texture/abc")
	if !d.Allow {
		t.Fatalf("official texture should be allowed: %+v", d)
	}
}

func TestClassifySkinURL_SubdomainAllowed(t *testing.T) {
	d := classifySkinURL("https://mc-heads.net/avatar/x.png")
	if !d.Allow {
		t.Fatalf("allowlisted domain should be allowed: %+v", d)
	}
}

func TestClassifySkinURL_HttpRejected(t *testing.T) {
	d := classifySkinURL("http://textures.minecraft.net/x.png")
	if d.Allow {
		t.Fatal("http must be rejected")
	}
}

func TestClassifySkinURL_UserInfoRejected(t *testing.T) {
	d := classifySkinURL("https://evil:pass@textures.minecraft.net/x.png")
	if d.Allow {
		t.Fatal("userinfo must be rejected")
	}
}

func TestClassifySkinURL_IPLiteralRejected(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "169.254.169.254", "[::1]"} {
		d := classifySkinURL("https://" + h + "/x.png")
		if d.Allow {
			t.Fatalf("ip literal %s must be rejected: %+v", h, d)
		}
	}
}

func TestClassifySkinURL_UnknownHostNotAutoAllowed(t *testing.T) {
	d := classifySkinURL("https://random-hacker.example/skin.png")
	if d.Allow {
		t.Fatal("unknown host must not be auto-allowed")
	}
}

func TestClassifySkinURL_EmptyAndGarbage(t *testing.T) {
	if d := classifySkinURL(""); d.Allow {
		t.Fatal("empty must be rejected")
	}
	if d := classifySkinURL("://nope"); d.Allow {
		t.Fatal("parse error must be rejected")
	}
}

func TestAllowSkinDownloadBool(t *testing.T) {
	if !allowSkinDownload("https://textures.minecraft.net/t") {
		t.Fatal("bool entry should allow official")
	}
	if allowSkinDownload("file:///etc/passwd") {
		t.Fatal("file scheme must be rejected")
	}
}
