package main

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestParseVersionParts(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		part int
	}{
		{"1.0.0", true, 3},
		{"1.0.0-beta", true, 4},
		{"2.3.4.5", true, 4},
		{"v1.2.3", true, 4},
		{"", false, 0},
		{"1..2", false, 0},
		{"1."+strings.Repeat("0", 200), false, 0},
		{"1\n2", false, 0},
	}
	for _, c := range cases {
		got := ParseVersionParts(c.in, UpdateLimits{})
		if c.ok != (got != nil) {
			t.Errorf("ParseVersionParts(%q) ok=%v want %v", c.in, got != nil, c.ok)
			continue
		}
		if c.ok && len(got) != c.part {
			t.Errorf("ParseVersionParts(%q) parts=%d want %d", c.in, len(got), c.part)
		}
	}
}

func TestCompareVersionTokens(t *testing.T) {
	cases := []struct{ a, b string; want int }{
		{"9.9", "9.10", -1},           // 经典字典序陷阱
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0-beta", "1.0.0", -1},   // beta 语义低于正式版
		{"1.0.0", "1.0.0-rc.1", 1},    // 正式版高于 rc
		{"2.0.0", "1.9.9", 1},
		{"1.10", "1.9", 1},
		{"10.0.0", "9.99.99", 1},
		{"1.0", "1.0.0", 0},           // 缺段按 0
	}
	for _, c := range cases {
		a := ParseVersionParts(c.a, UpdateLimits{})
		b := ParseVersionParts(c.b, UpdateLimits{})
		if a == nil || b == nil {
			t.Fatalf("version parse failed: %q %q", c.a, c.b)
		}
		got := CompareVersionTokens(a, b)
		if got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsVersionNewer(t *testing.T) {
	ok, err := IsVersionNewer("1.0.1", "1.0.0", UpdateLimits{})
	if err != nil || !ok {
		t.Fatalf("1.0.1 should be newer: ok=%v err=%v", ok, err)
	}
	ok, err = IsVersionNewer("1.0.0", "1.0.1", UpdateLimits{})
	if err != nil || ok {
		t.Fatalf("1.0.0 should not be newer: ok=%v err=%v", ok, err)
	}
	// 版本回滚防护：旧版号绝不允许通过。
	ok, _ = IsVersionNewer("0.9.0", "1.0.0", UpdateLimits{})
	if ok {
		t.Fatal("downgrade 0.9.0 -> 1.0.0 must be rejected")
	}
	// 数字 vs 字母 token：数字在前。
	ok, _ = IsVersionNewer("1.10", "1.9", UpdateLimits{})
	if !ok {
		t.Fatal("1.10 should be newer than 1.9")
	}
}

func TestSanitizeUpdateUrl(t *testing.T) {
	good := []string{
		"https://github.com/CN-RTStudio/OpenQGL/releases/download/v1.0.0/OpenQGL.zip",
		"https://objects.githubusercontent.com/xyz/OpenQGL.zip",
	}
	bad := []string{
		"http://github.com/x/y.zip",                    // 非 https
		"https://evil.example.com/x/y.zip",             // 白名单外域名
		"https://github.com.evil.com/x.zip",            // 前缀伪装的"子域"
		"https://user:pass@github.com/x.zip",           // 用户信息
		"https://1.2.3.4/x.zip",                        // IPv4 直连
		"https://[::1]:8080/x.zip",                     // IPv6 直连
		"https://github.com/" + strings.Repeat("a", 2100), // 超长
	}
	for _, u := range good {
		ok, host, reason := ValidateUpdateUrl(u, UpdateLimits{})
		if !ok {
			t.Errorf("URL should pass %q: %s", u, reason)
		}
		if host == "" {
			t.Errorf("host missing for %q", u)
		}
	}
	for _, u := range bad {
		ok, _, reason := ValidateUpdateUrl(u, UpdateLimits{})
		if ok {
			t.Errorf("URL should fail %q", u)
		}
		if reason == "" {
			t.Errorf("URL failure without reason %q", u)
		}
	}
}

func TestSanitizeUpdateAssetName(t *testing.T) {
	good := "OpenQGL-1.0.0-win64.zip"
	bad := []string{
		"", "a/b.zip", "..\\evil.zip", "a\u0000b.zip", "x\r\n.zip",
		strings.Repeat("n", 300) + ".zip",
	}
	if got, ok := ValidateUpdateAssetName(good, UpdateLimits{}); !ok || got != good {
		t.Fatalf("asset %q should pass", good)
	}
	for _, b := range bad {
		if _, ok := ValidateUpdateAssetName(b, UpdateLimits{}); ok {
			t.Errorf("asset should fail %q", b)
		}
	}
}

func TestSanitizeUpdateDesc(t *testing.T) {
	if _, ok := sanitizeUpdateDesc("修复了崩溃问题\n新增下载限速", UpdateLimits{}); !ok {
		t.Fatal("normal desc should pass")
	}
	if _, ok := sanitizeUpdateDesc("a\u0000b", UpdateLimits{}); ok {
		t.Fatal("NUL desc must fail")
	}
	// 超长（中文按 rune 计）。
	long := strings.Repeat("长", 3000)
	if _, ok := sanitizeUpdateDesc(long, UpdateLimits{}); ok {
		t.Fatal("overlong desc must fail")
	}
}

func TestInspectUpdateZipSafe(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"OpenQGL/QingLongLauncher.exe", "OpenQGL/readme.txt", "OpenQGL/lib/foo.dll"} {
		w, _ := zw.Create(name)
		w.Write([]byte("x"))
	}
	zw.Close()
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	v := InspectUpdateZip(zr, UpdateLimits{})
	if !v.OK {
		t.Fatalf("safe zip rejected: %s", SummarizeUpdateVerdict(v))
	}
	if !v.HasSingleRoot || !v.HasLauncherExe {
		t.Fatalf("expected single root + launcher exe: %s", SummarizeUpdateVerdict(v))
	}
	if v.ZipEntryCount != 3 {
		t.Fatalf("entry count=%d want 3", v.ZipEntryCount)
	}
}

func TestInspectUpdateZipPathTraversal(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Create("../evil.exe") // Zip Slip
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	v := InspectUpdateZip(zr, UpdateLimits{})
	if v.OK {
		t.Fatal("zip slip must be rejected")
	}
	if len(v.Findings) == 0 || v.Findings[0].Code != "zip-unsafe-path" {
		t.Fatalf("expected unsafe-path finding, got %v", v.Findings)
	}
}

func TestInspectUpdateZipNoLauncher(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Create("OpenQGL/data.txt")
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	v := InspectUpdateZip(zr, UpdateLimits{})
	if v.OK {
		t.Fatal("zip without launcher entry must be rejected")
	}
}

func TestInspectUpdateZipMultiRoot(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Create("a/QingLongLauncher.exe")
	zw.Create("b/data.txt")
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	v := InspectUpdateZip(zr, UpdateLimits{})
	if v.OK {
		t.Fatal("multi-root zip must be rejected")
	}
}

func TestInspectUpdateZipEntryOverflow(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 30; i++ {
		zw.Create("OpenQGL/f" + strings.Repeat("0", i) + ".dat")
	}
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	v := InspectUpdateZip(zr, UpdateLimits{ZipEntriesMax: 10})
	if v.OK {
		t.Fatal("entry overflow must be rejected")
	}
	if v.Findings[0].Code != "zip-entries-overflow" {
		t.Fatalf("unexpected code %v", v.Findings[0])
	}
}

func TestHasControlCharStr(t *testing.T) {
	if hasControlCharStr("clean-name") {
		t.Fatal("clean name flagged")
	}
	if !hasControlCharStr("a\u0000b") {
		t.Fatal("NUL not flagged")
	}
	if !hasControlCharStr("a\nb") {
		t.Fatal("newline not flagged")
	}
}

func TestUniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"b", "a", "b", "c", ""})
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("uniqueStrings got %v", got)
	}
}

func TestReadZipEntryTextBounded(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("note.txt")
	w.Write([]byte("hello world"))
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	text, err := readZipEntryText(zr.File[0], 100)
	if err != nil || text != "hello world" {
		t.Fatalf("read text err=%v text=%q", err, text)
	}
	if _, err := readZipEntryText(zr.File[0], 5); err == nil {
		t.Fatal("bounded read should fail beyond limit")
	}
}
