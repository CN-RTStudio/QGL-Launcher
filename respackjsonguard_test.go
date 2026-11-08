package main

import (
	"testing"
)

func TestPackAsset_Good(t *testing.T) {
	good := []string{
		"assets/minecraft/lang/zh_CN.json",
		"pack.mcmeta",
		"assets/foo/sounds/bar.ogg",
	}
	for _, g := range good {
		if err := ValidatePackAssetPath(g); err != nil {
			t.Fatalf("%s should pass: %v", g, err)
		}
	}
}

func TestPackAsset_Traversal(t *testing.T) {
	bad := []string{
		"../../etc/passwd",
		"a/../../b",
		"/etc/passwd",
		"C:/Windows/system32",
		"a//b",
		"",
		"a\x00b",
		"a\r\nb",
	}
	for _, b := range bad {
		if err := ValidatePackAssetPath(b); err == nil {
			t.Fatalf("%q must fail", b)
		}
	}
}

func TestFilterPackAssetList(t *testing.T) {
	in := []string{"ok/a", "../bad", "ok/b", "C:/x"}
	got := FilterPackAssetList(in)
	if len(got) != 2 {
		t.Fatalf("filtered = %v", got)
	}
}
