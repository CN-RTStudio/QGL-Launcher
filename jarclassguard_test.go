package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMavenCoord(t *testing.T) {
	lim := defaultJarClassLimits()
	cases := []struct {
		in        string
		wantOK    bool
		wantGroup string
		wantJar   string
	}{
		{"net.minecraft:client:1.20.1", true, "net.minecraft", "client-1.20.1.jar"},
		{"org.lwjgl:lwjgl:3.3.1:natives-windows", true, "org.lwjgl", "lwjgl-3.3.1-natives-windows.jar"},
		{"a:b", false, "", ""},
		{"a:b:", false, "", ""},
		{"a:b:c:d:e", false, "", ""},
		{"../../:evil:1.0", false, "", ""},
		{"a\\b:c:1", false, "", ""},
	}
	for _, c := range cases {
		g, a, v, cl, err := parseMavenCoord(c.in, lim)
		if c.wantOK && err != nil {
			t.Fatalf("%s: unexpected err %v", c.in, err)
		}
		if !c.wantOK && err == nil {
			t.Fatalf("%s: accepted", c.in)
		}
		if c.wantOK {
			if g != c.wantGroup {
				t.Fatalf("%s: group=%q want %q", c.in, g, c.wantGroup)
			}
			if jarFileName(a, v, cl) != c.wantJar {
				t.Fatalf("%s: jar=%q want %q", c.in, jarFileName(a, v, cl), c.wantJar)
			}
		}
	}
}

func TestValidateLibrarySet(t *testing.T) {
	lim := defaultJarClassLimits()
	good := []Library{
		{Name: "net.minecraft:client:1.20.1",
			Downloads: &LibDownloads{Artifact: &LibArtifact{Path: "libraries/net/minecraft/client/1.20.1/client-1.20.1.jar"}}},
		{Name: "org.lwjgl:lwjgl:3.3.1:natives-windows",
			Downloads: &LibDownloads{Classifiers: map[string]*LibArtifact{
				"natives-windows": {Path: "libraries/org/lwjgl/lwjgl/3.3.1/lwjgl-3.3.1-natives-windows.jar"},
			}}},
	}
	if vd := ValidateLibrarySet(good, lim); !vd.OK {
		t.Fatalf("good rejected: %s", vd.Reason)
	}

	bad := []struct {
		name string
		libs []Library
		want string
	}{
		{"coord-parts", []Library{{Name: "a:b"}}, "lib-name:"},
		{"dotdot", []Library{{Name: "a:b:1",
			Downloads: &LibDownloads{Artifact: &LibArtifact{Path: "libraries/a/b/1/../evil.jar"}}}}, "dotdot"},
		{"abs", []Library{{Name: "a:b:1",
			Downloads: &LibDownloads{Artifact: &LibArtifact{Path: "C:/evil.jar"}}}}, "abs-path"},
		{"dir-mismatch", []Library{{Name: "a:b:1",
			Downloads: &LibDownloads{Artifact: &LibArtifact{Path: "libraries/other/c/2/x.jar"}}}}, "dir-mismatch"},
		{"name-mismatch", []Library{{Name: "a:b:1",
			Downloads: &LibDownloads{Artifact: &LibArtifact{Path: "libraries/a/b/1/evil.jar"}}}}, "name-mismatch"},
		{"backslash", []Library{{Name: "a:b:1",
			Downloads: &LibDownloads{Artifact: &LibArtifact{Path: "libraries\\a\\b\\1\\b-1.jar"}}}}, "backslash"},
	}
	for _, c := range bad {
		vd := ValidateLibrarySet(c.libs, lim)
		if vd.OK || !strings.Contains(vd.Reason, c.want) {
			t.Fatalf("%s: ok=%v reason=%q want substring %q", c.name, vd.OK, vd.Reason, c.want)
		}
	}
}

func TestScanLibrariesDir(t *testing.T) {
	lim := defaultJarClassLimits()
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("net/minecraft/client/1.20.1/client-1.20.1.jar", "j1")
	write("org/lwjgl/lwjgl/3.3.1/lwjgl-3.3.1.jar", "j2")
	write("org/lwjgl/lwjgl/3.3.1/lwjgl-3.3.1-natives-windows.jar", "j3")
	write("bad/place/1/evil.jar", "j4")
	write("shallow/evil.jar", "j5")

	ok, bad := ScanLibrariesDir(root, lim)
	if ok {
		t.Fatalf("expected bad entries, got clean")
	}
	if len(bad) != 2 {
		t.Fatalf("bad count = %d want 2: %v", len(bad), bad)
	}
	joined := bad[0] + "|" + bad[1]
	if !strings.Contains(joined, "name-mismatch") || !strings.Contains(joined, "shallow-dir") {
		t.Fatalf("unexpected bad entries: %v", bad)
	}
}

func TestSummarizeJarClassVerdict(t *testing.T) {
	if s := SummarizeJarClassVerdict(jarClassVerdict{OK: true, Total: 3}); s != "jarclass clean total=3" {
		t.Fatalf("clean summary wrong: %q", s)
	}
	s := SummarizeJarClassVerdict(jarClassVerdict{OK: false, Bad: 2, Total: 4, Reason: "x"})
	if s != "jarclass bad=2 total=4 reason=x" {
		t.Fatalf("bad summary wrong: %q", s)
	}
}
