package main

import (
	"path/filepath"
	"testing"
)

func TestSafeMappingsVersionPathAcceptsLegitVersion(t *testing.T) {
	root := t.TempDir()
	cases := []string{"1.16.5", "1.13.2", "1.20.1-forge-47.2.0"}
	for _, version := range cases {
		p, ok := SafeMappingsVersionPath(root, version)
		if !ok {
			t.Fatalf("合法版本号 %q 应通过", version)
		}
		want := filepath.Join(root, "libraries", "net", "minecraft", "client", version,
			"client-"+version+"-mappings.txt")
		if p != want {
			t.Fatalf("路径不符: got %s want %s", p, want)
		}
	}
}

func TestSafeMappingsVersionPathRejectsTraversalForms(t *testing.T) {
	root := t.TempDir()
	bad := []string{
		"../../evil", "..", ".", "a/b", "a\\b", "", "1.16.5/../../escape",
		"C:", "con", "nul", "a b", "1.16.5:", "1.16.5.",
	}
	for _, version := range bad {
		if p, ok := SafeMappingsVersionPath(root, version); ok {
			t.Fatalf("应拒绝版本号 %q，却得到 %s", version, p)
		}
	}
}

func TestSafeMappingsVersionPathStaysInsideLibraries(t *testing.T) {
	root := t.TempDir()
	p, ok := SafeMappingsVersionPath(root, "1.16.5")
	if !ok {
		t.Fatal("合法版本号应通过")
	}
	if !PathWithinRoot(p, filepath.Join(root, "libraries")) {
		t.Fatalf("落盘路径越出 libraries: %s", p)
	}
}
