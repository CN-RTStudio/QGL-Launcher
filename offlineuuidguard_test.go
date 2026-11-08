package main

import (
	"strings"
	"testing"
)

func TestOfflineUUID_Deterministic(t *testing.T) {
	a, err := OfflineUUID("Notch")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := OfflineUUID("Notch")
	if a != b {
		t.Fatal("same name must derive same uuid")
	}
	if len(a) != 36 {
		t.Fatalf("uuid form must be 36 chars: %s", a)
	}
	if !IsOfflineUUID(a) {
		t.Fatalf("derived uuid must validate: %s", a)
	}
}

func TestOfflineUUID_TrimAndReject(t *testing.T) {
	if _, err := OfflineUUID("   "); err == nil {
		t.Fatal("blank name must error")
	}
	if _, err := OfflineUUID("a\nb"); err == nil {
		t.Fatal("newline in name must error")
	}
	a, _ := OfflineUUID("  Steve ")
	b, _ := OfflineUUID("Steve")
	if a != b {
		t.Fatalf("whitespace must be trimmed: %s vs %s", a, b)
	}
}

func TestIsOfflineUUID(t *testing.T) {
	good, _ := OfflineUUID("Herobrine")
	if !IsOfflineUUID(good) {
		t.Fatalf("derived uuid must validate: %s", good)
	}
	if !IsOfflineUUID(strings.ReplaceAll(good, "-", "")) {
		t.Fatal("undashed form must validate")
	}
	bad := []string{"", "not-a-uuid", "1-2-3", "00000000-0000-0000-0000-000000000000"}
	for _, s := range bad {
		if IsOfflineUUID(s) {
			t.Fatalf("must reject %q", s)
		}
	}
}
