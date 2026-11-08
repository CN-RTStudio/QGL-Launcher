package main

import (
	"testing"
)

func TestModCandidate_Good(t *testing.T) {
	good := []string{
		"jei-1.20.jar",
		"optifine.zip",
		"old-mod.jar.disabled",
		"/abs/path/mods/fabric-api.jar",
	}
	for _, g := range good {
		if !IsModCandidate(g) {
			t.Fatalf("%s should be candidate", g)
		}
	}
}

func TestModCandidate_Bad(t *testing.T) {
	bad := []string{
		"malware.exe",
		"run.bat",
		"evil.dll",
		".DS_Store",
		".hidden.jar",
		"notes.txt",
		"",
	}
	for _, b := range bad {
		if IsModCandidate(b) {
			t.Fatalf("%s must NOT be candidate", b)
		}
	}
}

func TestFilterModCandidates(t *testing.T) {
	in := []string{"a.jar", "b.exe", "c.zip", ".gitkeep"}
	got := FilterModCandidates(in)
	if len(got) != 2 {
		t.Fatalf("filtered = %v", got)
	}
}

func TestBlockedModExtReason(t *testing.T) {
	if BlockedModExtReason("a.jar") != "" {
		t.Fatal("allowed must have empty reason")
	}
	if BlockedModExtReason("b.exe") == "" {
		t.Fatal("blocked must have reason")
	}
}
