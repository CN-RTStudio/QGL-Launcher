package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorldMetaValidateName(t *testing.T) {
	lim := defaultWorldLimits()
	good := []string{"New World", "生存-01", "a", "world_2024"}
	bad := []struct {
		in   string
		want string
	}{
		{"", "empty"},
		{"../escape", "dotdot"},
		{"a/b", "separator"},
		{"a\\b", "separator"},
		{"/abs", "absolute"},
		{"C:evil", "absolute"},
		{"x\x01y", "control-char"},
		{strings.Repeat("a", 300), "too-long"},
	}
	for _, s := range good {
		if r := ValidateWorldName(s, lim); r != "" {
			t.Fatalf("%q rejected: %s", s, r)
		}
	}
	for _, c := range bad {
		if r := ValidateWorldName(c.in, lim); r != c.want {
			t.Fatalf("%q: got %q want %q", c.in, r, c.want)
		}
	}
}

func TestWorldMetaValidateDir(t *testing.T) {
	lim := defaultWorldLimits()
	root := t.TempDir()
	goodDir := filepath.Join(root, "MyWorld")
	if err := os.MkdirAll(filepath.Join(goodDir, "region"), 0o755); err != nil {
		t.Fatal(err)
	}
	// 伪造最小 level.dat：裸 NBT 魔数 + 填充
	if err := os.WriteFile(filepath.Join(goodDir, "level.dat"), []byte{0x0a, 0x00, 0x00, 0x00, 0x00, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	vd := ValidateWorldDir(goodDir, lim)
	if !vd.OK {
		t.Fatalf("good world rejected: %s", vd.Reason)
	}

	// 缺 level.dat
	emptyDir := filepath.Join(root, "Empty")
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if vd := ValidateWorldDir(emptyDir, lim); vd.OK {
		t.Fatalf("empty world accepted")
	}

	// 坏魔数
	badDat := filepath.Join(root, "BadDat")
	if err := os.MkdirAll(badDat, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDat, "level.dat"), []byte{0x99, 0x00, 0x00, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	if vd := ValidateWorldDir(badDat, lim); vd.OK || !containsReason(vd.Reason, "magic") {
		t.Fatalf("bad magic accepted or wrong reason: %v", vd)
	}

	// 符号链接目录
	symDir := filepath.Join(root, "Linked")
	if err := os.Symlink(goodDir, symDir); err == nil {
		if vd := ValidateWorldDir(symDir, lim); vd.OK || !containsReason(vd.Reason, "dir-symlink") {
			t.Fatalf("symlink dir accepted: %v", vd)
		}
	}
}

func TestScanSavesDir(t *testing.T) {
	lim := defaultWorldLimits()
	root := t.TempDir()
	good := filepath.Join(root, "WorldA")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(good, "level.dat"), []byte{0x1f, 0x8b, 0x00, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "..bad"), 0o755); err != nil {
		t.Fatal(err)
	}
	ok, bads := ScanSavesDir(root, lim)
	if ok {
		t.Fatalf("expected bad entries")
	}
	if len(bads) != 1 || !containsReason(bads[0], "name:dotdot") {
		t.Fatalf("unexpected bads: %v", bads)
	}
}

func TestSummarizeWorldVerdict(t *testing.T) {
	if s := SummarizeWorldVerdict(worldVerdict{OK: true}); s != "world ok" {
		t.Fatalf("summary wrong: %q", s)
	}
	if s := SummarizeWorldVerdict(worldVerdict{OK: true, HasBack: true}); s != "world ok (backup level.dat_old)" {
		t.Fatalf("summary wrong: %q", s)
	}
	if s := SummarizeWorldVerdict(worldVerdict{OK: false, Reason: "magic"}); s != "world bad magic" {
		t.Fatalf("summary wrong: %q", s)
	}
}

func containsReason(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
