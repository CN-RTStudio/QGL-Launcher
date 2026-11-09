package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoaderArtifactExt(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"plain jar", "https://maven.example.com/forge-installer.jar", ".jar"},
		{"jar with query", "https://maven.example.com/forge-installer.jar?token=abc&d=1", ".jar"},
		{"jar with fragment", "https://maven.example.com/forge-installer.jar#section", ".jar"},
		{"uppercase jar", "https://maven.example.com/Forge-Installer.JAR", ".jar"},
		{"exe", "https://maven.example.com/jre-setup.exe", ".exe"},
		{"exe with query", "https://maven.example.com/jre-setup.exe?X-Goog=1", ".exe"},
		{"no extension", "https://maven.example.com/download/123", ""},
		{"extension before query is not suffix", "https://h/x.jar/run?a=.exe", ""},
		{"empty", "", ""},
		{"spaces", "   https://h/a.jar  ", ".jar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := loaderArtifactExt(tc.url); got != tc.want {
				t.Fatalf("loaderArtifactExt(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

func TestSanitizeLoaderSlug(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"forge 47.2.0 (1.20.1)", "forge_47.2.0_1.20.1"},
		{"  --leading--", "leading"},
		{"trailing...", "trailing"},
		{"a   b", "a_b"},
		{"a(((b", "a_b"},
		{"../../etc", "etc"},
		{"完全是中文", ""},
		{"混合 mix 名称", "mix"},
		{"CON", "CON"},
		{"a--b__c", "a-b_c"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := sanitizeLoaderSlug(tc.in); got != tc.want {
				t.Fatalf("sanitizeLoaderSlug(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	long := strings.Repeat("a", maxLoaderSlugLen+50)
	got := sanitizeLoaderSlug(long)
	if len(got) > maxLoaderSlugLen {
		t.Fatalf("slug length %d exceeds cap %d", len(got), maxLoaderSlugLen)
	}
}

func TestBuildLoaderDestNameShape(t *testing.T) {
	name := buildLoaderDestName("forge 47.2.0 (1.20.1)", "https://h/forge.jar?x=1", ".jar")
	if !strings.HasSuffix(name, ".jar") {
		t.Fatalf("name %q must end with .jar", name)
	}
	if len(name) > maxLoaderDestSegLen {
		t.Fatalf("name length %d exceeds %d", len(name), maxLoaderDestSegLen)
	}
	if !validateSafeSegment(name) {
		t.Fatalf("generated name %q failed validateSafeSegment", name)
	}
	// 指纹段固定 16 个十六进制字符，位于最后一个扩展名之前。
	stem := strings.TrimSuffix(name, ".jar")
	hashPart := stem[strings.LastIndexByte(stem, '-')+1:]
	if len(hashPart) != loaderURLHashLen {
		t.Fatalf("hash segment %q length = %d, want %d", hashPart, len(hashPart), loaderURLHashLen)
	}
	for _, c := range hashPart {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Fatalf("hash segment %q contains non-hex %q", hashPart, c)
		}
	}
}

func TestBuildLoaderDestNameDeterminismAndIsolation(t *testing.T) {
	custom := "forge 47.2.0 (1.20.1)"
	u1 := "https://maven.example.com/a.jar"
	u2 := "https://maven.example.com/b.jar"

	n1 := buildLoaderDestName(custom, u1, ".jar")
	n1Again := buildLoaderDestName(custom, u1, ".jar")
	n2 := buildLoaderDestName(custom, u2, ".jar")

	if n1 != n1Again {
		t.Fatalf("same URL must map to same name: %q vs %q", n1, n1Again)
	}
	if n1 == n2 {
		t.Fatalf("different URLs with identical display name must not collide: %q", n1)
	}
}

func TestBuildLoaderDestNameReservedEscaped(t *testing.T) {
	// 展示名直接命中 Windows 保留设备名时，加上指纹后缀后整段不再是保留名。
	for _, reserved := range []string{"CON", "PRN", "AUX", "NUL", "COM1", "LPT9"} {
		name := buildLoaderDestName(reserved, "https://h/"+strings.ToLower(reserved)+".jar", ".jar")
		if !validateSafeSegment(name) {
			t.Fatalf("reserved display %q produced unsafe segment %q", reserved, name)
		}
	}
}

func TestResolveLoaderTempDestContainment(t *testing.T) {
	tempDir := filepath.Clean("/tmp/openqgl-loader-test")
	hostile := []string{
		"../../../Windows/System32/evil",
		"..\\..\\windows",
		"CON",
		"a/b/c",
		"",
	}
	for _, cn := range hostile {
		dest, ok := resolveLoaderTempDest(tempDir, cn, "https://h/installer.jar")
		if !ok {
			t.Fatalf("resolveLoaderTempDest(custom=%q) rejected unexpectedly", cn)
		}
		if !PathWithinRoot(dest, tempDir) {
			t.Fatalf("dest %q escaped root %q for custom %q", dest, tempDir, cn)
		}
		base := filepath.Base(dest)
		if !validateSafeSegment(base) {
			t.Fatalf("dest base %q unsafe for custom %q", base, cn)
		}
	}
}

func TestResolveLoaderTempDestDistinctURLs(t *testing.T) {
	tempDir := filepath.Clean("/tmp/openqgl-loader-test")
	d1, ok1 := resolveLoaderTempDest(tempDir, "forge 1 (1.0)", "https://h/a.jar")
	d2, ok2 := resolveLoaderTempDest(tempDir, "forge 1 (1.0)", "https://h/b.jar")
	if !ok1 || !ok2 {
		t.Fatalf("resolve failed: %v %v", ok1, ok2)
	}
	if d1 == d2 {
		t.Fatalf("identical custom name but different URLs must land in distinct files: %q", d1)
	}
	if strings.EqualFold(filepath.Dir(d1), filepath.Clean(d1)) {
		t.Fatalf("dest must not equal a drive root: %q", d1)
	}
}

func TestResolveLoaderTempDestBadRoots(t *testing.T) {
	if _, ok := resolveLoaderTempDest("", "forge", "https://h/a.jar"); ok {
		t.Fatal("empty temp dir must be rejected")
	}
	if _, ok := resolveLoaderTempDest(".", "forge", "https://h/a.jar"); ok {
		t.Fatal("relative/empty-equivalent temp dir must be rejected")
	}
}
