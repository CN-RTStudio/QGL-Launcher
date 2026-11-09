package main

import "testing"

func TestAuditDownloadQueueURLAccepts(t *testing.T) {
	cases := []string{
		"https://piston-data.mojang.com/v1/objects/ab/cd.jar",
		"https://example.test/1.20.1.json",
		"http://example.test/a.jar",
		"HTTPS://example.test/a.jar",
		"https://example.test:443/a.jar",
		"http://example.test:80/a.jar",
		"https://example.test/a?x=1&y=2#frag",
		"https://example.test./a.jar",
		"https://a_b.example.test/a.jar",
		"",
	}
	for _, in := range cases {
		if got := auditDownloadQueueURL(in); got != dqURLRejectNone {
			t.Fatalf("auditDownloadQueueURL(%q)=%q want none", in, got)
		}
	}
}

func TestAuditDownloadQueueURLRejects(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"file:///etc/passwd", dqURLRejectScheme},
		{"ftp://example.test/a.jar", dqURLRejectScheme},
		{"javascript:alert(1)", dqURLRejectScheme},
		{"data:text/plain,abc", dqURLRejectScheme},
		{"https://user:pass@example.test/a.jar", dqURLRejectUserinfo},
		{"https://example.test@evil.test/a.jar", dqURLRejectUserinfo},
		{"https://example.test\\@evil.test/a.jar", dqURLRejectBackslash},
		{"https://example.test/a\\b.jar", dqURLRejectBackslash},
		{"https://example.test/a b.jar", dqURLRejectControl},
		{"https://example.test/a\nb.jar", dqURLRejectControl},
		{"https://example.test/a\x7fb.jar", dqURLRejectControl},
		{"https://example.test/中文.jar", dqURLRejectEncoding},
		{"https://exa%6dple.test/a.jar", dqURLRejectEncoding},
		{"https://127.0.0.1/a.jar", dqURLRejectIPLiteral},
		{"https://2130706433/a.jar", dqURLRejectIPLiteral},
		{"https://0x7f000001/a.jar", dqURLRejectIPLiteral},
		{"https://[::1]/a.jar", dqURLRejectIPLiteral},
		{"https://example.test:8443/a.jar", dqURLRejectPort},
		{"http://example.test:443/a.jar", dqURLRejectPort},
		{"https:///missing-host", dqURLRejectMalformed},
		{"https://", dqURLRejectMalformed},
		{"https:example.test", dqURLRejectMalformed},
		{"//example.test/a.jar", dqURLRejectMalformed},
		{"https://.example.test/a.jar", dqURLRejectHost},
		{"https://a..b.test/a.jar", dqURLRejectHost},
		{"https://-bad.test/a.jar", dqURLRejectHost},
		{"https://bad-.test/a.jar", dqURLRejectHost},
		{"https://localhost/a.jar", dqURLRejectHost},
		{"https://example.123/a.jar", dqURLRejectHost},
		{"https://" + repeatAscii(64) + ".test/a.jar", dqURLRejectHost},
	}
	for _, c := range cases {
		if got := auditDownloadQueueURL(c.in); got != c.want {
			t.Fatalf("auditDownloadQueueURL(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestAuditDownloadQueueURLRejectsLong(t *testing.T) {
	long := "https://example.test/" + repeatAscii(5000)
	if got := auditDownloadQueueURL(long); got != dqURLRejectLong {
		t.Fatalf("long url = %q want %q", got, dqURLRejectLong)
	}
}

func repeatAscii(n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = 'a'
	}
	return string(buf)
}

func TestDescribeDownloadURLReject(t *testing.T) {
	all := []string{
		dqURLRejectScheme, dqURLRejectUserinfo, dqURLRejectControl, dqURLRejectBackslash,
		dqURLRejectHost, dqURLRejectIPLiteral, dqURLRejectPort, dqURLRejectMalformed,
		dqURLRejectEncoding, dqURLRejectLong,
	}
	seen := map[string]bool{}
	for _, code := range all {
		text := describeDownloadURLReject(code)
		if text == "" {
			t.Fatalf("empty text for %q", code)
		}
		if seen[text] {
			t.Fatalf("duplicate text %q", text)
		}
		seen[text] = true
	}
	if got := describeDownloadURLReject("unknown-code"); got == "" {
		t.Fatalf("fallback text is empty")
	}
}

func TestDownloadQueueRejectsUnsafeURL(t *testing.T) {
	base := DownloadItem{ID: "x", ItemType: "game", CustomName: "1.20.1", URL: "https://example.test/1.20.1.json"}
	if why := auditDownloadItemForEnqueue(nil, base); why != dqRejectNone {
		t.Fatalf("safe item rejected: %q", why)
	}
	bad := []string{
		"file:///etc/passwd",
		"https://user:pass@example.test/a.jar",
		"https://example.test\\a.jar",
	}
	for _, u := range bad {
		item := base
		item.URL = u
		if why := auditDownloadItemForEnqueue(nil, item); why != dqRejectBadURL {
			t.Fatalf("unsafe url %q got %q want %q", u, why, dqRejectBadURL)
		}
	}
}
