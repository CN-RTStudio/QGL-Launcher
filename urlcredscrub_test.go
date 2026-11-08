package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestScrubUserInfoPassword(t *testing.T) {
	pol := defaultURLScrubPolicy()
	u, _ := url.Parse("https://alice:hunter2@api.example.com/v1/data")
	out, reds := ScrubURL(u, pol)
	if !strings.Contains(out, "***") || strings.Contains(out, "hunter2") {
		t.Fatalf("password not scrubbed: %s", out)
	}
	found := false
	for _, r := range reds {
		if r.Location == "userinfo" && r.Reason == "userinfo-password" {
			found = true
		}
	}
	if !found {
		t.Fatalf("userinfo redaction missing: %+v", reds)
	}
	// 原 URL 不被修改。
	if !strings.Contains(u.String(), "hunter2") {
		t.Fatal("ScrubURL must not mutate input URL")
	}
}

func TestScrubSensitiveQueryKeys(t *testing.T) {
	pol := defaultURLScrubPolicy()
	raw := "https://api.example.com/x?access_token=abcdef&page=2"
	u, _ := url.Parse(raw)
	out, reds := ScrubURL(u, pol)
	if !HasSensitiveRedaction(reds) {
		t.Fatalf("expected redaction for %s", raw)
	}
	if strings.Contains(out, "abcdef") {
		t.Fatalf("secret token leaked into %s", out)
	}
	if !strings.Contains(out, "page=2") {
		t.Fatalf("safe param should survive: %s", out)
	}
	for _, raw := range []string{
		"https://api.example.com/x?refresh_token=rtsecretvalue&lang=en",
		"https://api.example.com/x?client_secret=cssecretvalue",
		"https://api.example.com/x?Signature=sigsecretvalue",
	} {
		u, _ := url.Parse(raw)
		out, reds := ScrubURL(u, pol)
		if !HasSensitiveRedaction(reds) {
			t.Fatalf("expected redaction for %s", raw)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Fatalf("secret value should be replaced in %s", out)
		}
	}
}

func TestScrubKeepsSafePagingParams(t *testing.T) {
	pol := defaultURLScrubPolicy()
	u, _ := url.Parse("https://api.example.com/list?page=3&size=50&version=1.20")
	out, reds := ScrubURL(u, pol)
	if !strings.Contains(out, "page=3") || !strings.Contains(out, "size=50") || !strings.Contains(out, "version=1.20") {
		t.Fatalf("safe params should be preserved: %s", out)
	}
	if len(reds) != 0 {
		t.Fatalf("no redaction expected, got %+v", reds)
	}
}

func TestScrubHighEntropyValueUnderBenignKey(t *testing.T) {
	pol := defaultURLScrubPolicy()
	// 良性键 data 携带长十六进制令牌。
	u, _ := url.Parse("https://api.example.com/x?data=0123456789abcdef0123456789abcdef0123456789abcdef")
	out, reds := ScrubURL(u, pol)
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("high-entropy value should be redacted: %s", out)
	}
	if !hasReason(reds, "high-entropy-query-value") {
		t.Fatalf("expected high-entropy reason, got %+v", reds)
	}
}

func TestScrubJWTValue(t *testing.T) {
	pol := defaultURLScrubPolicy()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	u, _ := url.Parse("https://api.example.com/x?redirect=/home&id=" + jwt)
	_, reds := ScrubURL(u, pol)
	if !hasReason(reds, "high-entropy-query-value") {
		t.Fatalf("jwt value should be flagged: %+v", reds)
	}
}

func TestScrubBearerValue(t *testing.T) {
	pol := defaultURLScrubPolicy()
	u, _ := url.Parse("https://api.example.com/x?note=Bearer%20abcdefghijklmnopqrstuvwxyz0123456789ABCD")
	_, reds := ScrubURL(u, pol)
	if !hasReason(reds, "high-entropy-query-value") {
		t.Fatalf("bearer value should be flagged: %+v", reds)
	}
}

func TestScrubFragmentDropped(t *testing.T) {
	pol := defaultURLScrubPolicy()
	u, _ := url.Parse("https://app.example.com/cb#access_token=fragtoken&state=xyz")
	out, reds := ScrubURL(u, pol)
	if strings.Contains(out, "fragtoken") {
		t.Fatalf("fragment secret leaked: %s", out)
	}
	if !hasLocation(reds, "fragment") {
		t.Fatalf("fragment should be dropped: %+v", reds)
	}
}

func TestScrubBenignFragmentKeptWhenDisabled(t *testing.T) {
	pol := defaultURLScrubPolicy()
	pol.DropFragment = false
	u, _ := url.Parse("https://app.example.com/page#section-2")
	out, reds := ScrubURL(u, pol)
	if !strings.Contains(out, "section-2") {
		t.Fatalf("benign anchor should be kept: %s", out)
	}
	if len(reds) != 0 {
		t.Fatalf("benign fragment should not redact: %+v", reds)
	}
}

func TestScrubExtraSensitiveKey(t *testing.T) {
	pol := defaultURLScrubPolicy()
	pol.ExtraSensitiveQuery = map[string]struct{}{"x-custom-auth": {}}
	u, _ := url.Parse("https://api.example.com/x?x-custom-auth=zzzz")
	_, reds := ScrubURL(u, pol)
	if !hasReason(reds, "sensitive-query-key") {
		t.Fatalf("extra sensitive key should be flagged: %+v", reds)
	}
}

func TestScrubURLStringUnparseable(t *testing.T) {
	out, reds := ScrubURLString("://:not a url%%%", defaultURLScrubPolicy())
	if out != "(unparseable-url)" {
		t.Fatalf("unparseable should be masked, got %s", out)
	}
	if len(reds) == 0 {
		t.Fatal("expected redaction for unparseable url")
	}
}

func TestScrubNilURL(t *testing.T) {
	out, reds := ScrubURL(nil, defaultURLScrubPolicy())
	if out != "" || len(reds) != 0 {
		t.Fatalf("nil url should yield empty, got %q %+v", out, reds)
	}
}

func TestScrubShortNumericValueKept(t *testing.T) {
	pol := defaultURLScrubPolicy()
	// 非保留键但值为短数字，不达高熵阈值，应原样保留。
	u, _ := url.Parse("https://api.example.com/x?count=42")
	out, reds := ScrubURL(u, pol)
	if !strings.Contains(out, "count=42") {
		t.Fatalf("short numeric should be kept: %s", out)
	}
	if len(reds) != 0 {
		t.Fatalf("short numeric should not redact: %+v", reds)
	}
}

func hasReason(reds []URLRedaction, reason string) bool {
	for _, r := range reds {
		if r.Reason == reason {
			return true
		}
	}
	return false
}

func hasLocation(reds []URLRedaction, loc string) bool {
	for _, r := range reds {
		if r.Location == loc {
			return true
		}
	}
	return false
}
