package main

import (
	"strings"
	"testing"
)

func TestQueueGuardValidateURL(t *testing.T) {
	lim := defaultQueueLimits()
	good := []string{
		"https://launcher.mojang.com/v1/objects/x/client.jar",
		"https://piston-meta.mojang.com/mc/game/version_manifest.json",
		"http://bmclapi2.bangbang93.com/version/1.20.1",
		"https://cdn.modrinth.com/data/proj/versions/v.jar",
	}
	for _, s := range good {
		if r := validateQueueURL(s, lim); r != "" {
			t.Fatalf("%q rejected: %s", s, r)
		}
	}
	bad := []struct{ in, want string }{
		{"ftp://launcher.mojang.com/x", "url-scheme"},
		{"https://user:pass@launcher.mojang.com/x", "url-userinfo"},
		{"https://evil.com/x.jar", "url-host:"},
		{"https://launcher.mojang.com:9999/x", "url-host:"},
		{"https://192.168.1.1/x", "url-host:"},
		{"", "url-parse-fail"},
	}
	for _, c := range bad {
		r := validateQueueURL(c.in, lim)
		if r == "" || !strings.Contains(r, c.want) {
			t.Fatalf("%q: got %q want %q", c.in, r, c.want)
		}
	}
}

func TestQueueGuardValidateDest(t *testing.T) {
	lim := defaultQueueLimits()
	good := []string{"libraries/net/minecraft/client-1.20.1.jar", "versions/1.20.1/1.20.1.json", "a/b/c.jar"}
	for _, s := range good {
		if r := validateQueueDest(s, lim); r != "" {
			t.Fatalf("%q rejected: %s", s, r)
		}
	}
	bad := []struct{ in, want string }{
		{"../evil.jar", "dest-dotdot"},
		{"/abs.jar", "dest-absolute"},
		{"C:evil.jar", "dest-absolute"},
		{"a\\b.jar", "dest-backslash"},
		{"", "dest-empty"},
	}
	for _, c := range bad {
		r := validateQueueDest(c.in, lim)
		if r == "" || !strings.Contains(r, c.want) {
			t.Fatalf("%q: got %q want %q", c.in, r, c.want)
		}
	}
}

func TestQueueGuardHash(t *testing.T) {
	if r := validateQueueHash(""); r != "" {
		t.Fatalf("empty hash rejected: %s", r)
	}
	if r := validateQueueHash(strings.Repeat("a", 40)); r != "" {
		t.Fatalf("sha1 rejected: %s", r)
	}
	if r := validateQueueHash(strings.Repeat("A", 64)); r != "" {
		t.Fatalf("sha256 rejected: %s", r)
	}
	for _, h := range []string{strings.Repeat("a", 41), "zz" + strings.Repeat("a", 38), "x"} {
		if r := validateQueueHash(h); r == "" {
			t.Fatalf("%q accepted", h)
		}
	}
}

func TestAuditDownloadQueue(t *testing.T) {
	lim := defaultQueueLimits()
	good := []queueItem{
		{URL: "https://launcher.mojang.com/v1/objects/a/client.jar", Dest: "versions/1.20.1/1.20.1.jar", Hash: strings.Repeat("a", 40), Size: 1000},
		{URL: "https://cdn.modrinth.com/data/x/y.jar", Dest: "mods/y.jar", Size: 500},
	}
	vd := AuditDownloadQueue(good, lim)
	if !vd.OK {
		t.Fatalf("good rejected: %s", vd.Reason)
	}
	if len(vd.Clean) != 2 || vd.Total != 1500 {
		t.Fatalf("clean=%d total=%d", len(vd.Clean), vd.Total)
	}
	bad := []struct {
		name string
		it   queueItem
		want string
	}{
		{"ssrf", queueItem{URL: "https://10.0.0.1/x", Dest: "a.jar"}, "url-host:"},
		{"dest-escape", queueItem{URL: "https://launcher.mojang.com/x", Dest: "../evil.jar"}, "dest-dotdot"},
		{"hash", queueItem{URL: "https://launcher.mojang.com/x", Dest: "a.jar", Hash: "zz"}, "hash"},
		{"neg-size", queueItem{URL: "https://launcher.mojang.com/x", Dest: "a.jar", Size: -1}, "size-negative"},
	}
	for _, c := range bad {
		vd := AuditDownloadQueue([]queueItem{c.it}, lim)
		if vd.OK || !strings.Contains(vd.Reason, c.want) {
			t.Fatalf("%s: ok=%v reason=%q", c.name, vd.OK, vd.Reason)
		}
	}
}

func TestSummarizeQueueVerdict(t *testing.T) {
	if s := SummarizeQueueVerdict(queueVerdict{OK: true, Total: 2 << 20}); s != "queue ok entries=0 totalMB=2" {
		t.Fatalf("summary wrong: %q", s)
	}
	if s := SummarizeQueueVerdict(queueVerdict{OK: false, Reason: "url-host:evil.com"}); s != "queue bad url-host:evil.com" {
		t.Fatalf("summary wrong: %q", s)
	}
}

// TestSplitQueueAuthority 覆盖 authority 拆分的全部形态：域名、域名+端口、
// 方括号 IPv6、裸 IPv6、非法形态（多冒号、空端口、混入路径分隔符）。
func TestSplitQueueAuthority(t *testing.T) {
	ok := []struct{ in, host, port string }{
		{"cdn.modrinth.com", "cdn.modrinth.com", ""},
		{"cdn.modrinth.com:8443", "cdn.modrinth.com", "8443"},
		{"CDN.Modrinth.COM.:443", "CDN.Modrinth.COM.", "443"},
		{"[::1]:443", "[::1]", "443"},
		{"[::1]", "[::1]", ""},
		{"2001:db8::1", "2001:db8::1", ""},
	}
	for _, c := range ok {
		host, port, valid := splitQueueAuthority(c.in)
		if !valid || host != c.host || port != c.port {
			t.Fatalf("splitQueueAuthority(%q) = (%q,%q,%v)", c.in, host, port, valid)
		}
	}
	bad := []string{
		"", "   ", "host:", ":443", "[::1", "[::1]x", "a:b:c", "https://x.com", "x.com/y",
		"user@x.com", "x.com#f", "x y.com",
	}
	for _, in := range bad {
		h, p, valid := splitQueueAuthority(in)
		if valid {
			t.Fatalf("splitQueueAuthority(%q) valid, got (%q,%q)", in, h, p)
		}
	}
}

// TestHostAllowedQPorts 覆盖端口白名单与 IPv6：旧实现用 LastIndex(":") 剥端口，
// IPv6 必然被切坏，而无端口主机又完全跳过端口校验。
func TestHostAllowedQPorts(t *testing.T) {
	lim := defaultQueueLimits()
	yes := []string{
		"cdn.modrinth.com",
		"cdn.modrinth.com:443",
		"cdn.modrinth.com:80",
		"cdn.modrinth.com:8080",
		"cdn.modrinth.com:8443",
		"cdn.modrinth.com.",
		"CDN.MODRINTH.COM:443",
	}
	for _, h := range yes {
		if !hostAllowedQ(h, lim) {
			t.Fatalf("hostAllowedQ(%q) = false, want true", h)
		}
	}
	no := []string{
		"cdn.modrinth.com:22",
		"cdn.modrinth.com:4430",
		"cdn.modrinth.com:",
		":443",
		"[::1]:443",
		"[2001:db8::1]:443",
		"2001:db8::1",
		"evil.com",
		"cdn.modrinth.com.evil.com",
		"cdn.modrinth.com/x",
	}
	for _, h := range no {
		if hostAllowedQ(h, lim) {
			t.Fatalf("hostAllowedQ(%q) = true, want false", h)
		}
	}
	// 自定义白名单里的 IPv6 字面量必须能命中（带不带端口都行）。
	custom := QueueLimits{
		MaxEntries:   100,
		MaxTotalSize: 1 << 30,
		MaxNameLen:   128,
		AllowedHosts: []string{"[::1]", "[2001:db8::1]"},
		AllowedPorts: map[string]bool{"443": true},
	}
	if !hostAllowedQ("[::1]:443", custom) {
		t.Fatal("custom IPv6 host with port rejected")
	}
	if !hostAllowedQ("[2001:db8::1]", custom) {
		t.Fatal("custom IPv6 host without port rejected")
	}
	if hostAllowedQ("[::1]:80", custom) {
		t.Fatal("custom IPv6 host on disallowed port accepted")
	}
	// 空端口表表示不限制端口。
	openPorts := custom
	openPorts.AllowedPorts = nil
	if !hostAllowedQ("[::1]:80", openPorts) {
		t.Fatal("port-restriction disabled but host rejected")
	}
}

// TestValidateQueueURLHostStructure 覆盖 URL 层的结构拒绝：不透明形式、
// 百分号编码主机、空主机、超长串。
func TestValidateQueueURLHostStructure(t *testing.T) {
	lim := defaultQueueLimits()
	bad := []struct{ in, want string }{
		{"https:opaque", "url-opaque"},
		{"https://", "url-no-host"},
		{"https://:443/x", "url-no-host"},
		{"https://[fe80::1%25eth0]/x.jar", "url-host-encoded"},
	}
	for _, c := range bad {
		if r := validateQueueURL(c.in, lim); !strings.Contains(r, c.want) {
			t.Fatalf("%q: got %q want %q", c.in, r, c.want)
		}
	}
	// 百分号编码的普通主机名连 url.Parse 都过不了，同样不允许进队。
	if r := validateQueueURL("https://%31%32%37.0.0.1/x.jar", lim); r == "" {
		t.Fatal("percent-encoded host accepted")
	}
	if r := validateQueueURL("https://launcher.mojang.com:8443/x", lim); r != "" {
		t.Fatalf("8443 should be allowed: %s", r)
	}
	if r := validateQueueURL("https://launcher.mojang.com:22/x", lim); !strings.Contains(r, "url-host:") {
		t.Fatalf("22 should be rejected: %s", r)
	}
}
