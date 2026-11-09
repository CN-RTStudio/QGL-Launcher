package main

import (
	"errors"
	"testing"
)

func TestBombPolicyRejectsZeroValue(t *testing.T) {
	if _, err := NewArchiveBombAuditor(ArchiveBombPolicy{}); err == nil {
		t.Fatal("zero-value policy must be rejected")
	}
}

func TestBombAllowsNormalArchive(t *testing.T) {
	a, err := NewArchiveBombAuditor(DefaultArchiveBombPolicy())
	if err != nil {
		t.Fatal(err)
	}
	normal := []EntryInput{
		{Name: "mods/", IsDir: true},
		{Name: "mods/a.jar", Compressed: 1000, Uncompressed: 4000},
		{Name: "mods/b.jar", Compressed: 2000, Uncompressed: 5000},
	}
	for i, e := range normal {
		if err := a.AddEntry(e); err != nil {
			t.Fatalf("entry %d rejected: %v", i, err)
		}
	}
	if n, tot, _, _ := a.Snapshot(); n != 3 || tot != 9000 {
		t.Fatalf("snapshot wrong: n=%d tot=%d", n, tot)
	}
}

func TestBombRejectsHighRatio(t *testing.T) {
	p := DefaultArchiveBombPolicy()
	p.MaxCompressionRatio = 100
	a, _ := NewArchiveBombAuditor(p)
	err := a.AddEntry(EntryInput{Name: "boom.bin", Compressed: 1, Uncompressed: 1 << 20})
	if !IsBombError(err) {
		t.Fatalf("expected bomb error, got %v", err)
	}
	var be BombError
	if !errors.As(err, &be) {
		t.Fatal("error must satisfy BombError")
	}
	if be.BombReason() != BombReasonRatio {
		t.Fatalf("reason=%s", be.BombReason())
	}
}

func TestBombRejectsSingleHugeEntry(t *testing.T) {
	a, _ := NewArchiveBombAuditor(DefaultArchiveBombPolicy())
	err := a.AddEntry(EntryInput{Name: "x", Compressed: 1 << 20, Uncompressed: 1 << 30})
	if err == nil || !IsBombError(err) {
		t.Fatalf("expected single-entry bomb, got %v", err)
	}
}

func TestBombRejectsCumulativeTotal(t *testing.T) {
	p := DefaultArchiveBombPolicy()
	p.MaxUncompressedTotal = 1000
	a, _ := NewArchiveBombAuditor(p)
	if err := a.AddEntry(EntryInput{Name: "a", Compressed: 10, Uncompressed: 600}); err != nil {
		t.Fatal(err)
	}
	err := a.AddEntry(EntryInput{Name: "b", Compressed: 10, Uncompressed: 600})
	if err == nil {
		t.Fatal("cumulative overflow must be rejected")
	}
}

func TestBombRejectsTooManyEntries(t *testing.T) {
	p := DefaultArchiveBombPolicy()
	p.MaxEntries = 2
	a, _ := NewArchiveBombAuditor(p)
	_ = a.AddEntry(EntryInput{Name: "a", IsDir: true})
	_ = a.AddEntry(EntryInput{Name: "b", IsDir: true})
	err := a.AddEntry(EntryInput{Name: "c", IsDir: true})
	if err == nil {
		t.Fatal("third entry must exceed count cap")
	}
}

func TestBombRejectsDuplicateName(t *testing.T) {
	a, _ := NewArchiveBombAuditor(DefaultArchiveBombPolicy())
	if err := a.AddEntry(EntryInput{Name: "same.jar", Compressed: 1, Uncompressed: 2}); err != nil {
		t.Fatal(err)
	}
	err := a.AddEntry(EntryInput{Name: "same.jar", Compressed: 1, Uncompressed: 2})
	if err == nil {
		t.Fatal("duplicate name must be rejected")
	}
}

func TestBombRejectsLongName(t *testing.T) {
	p := DefaultArchiveBombPolicy()
	p.MaxNameLen = 4
	a, _ := NewArchiveBombAuditor(p)
	if err := a.AddEntry(EntryInput{Name: "abcd"}); err != nil {
		t.Fatal("boundary length should pass")
	}
	if err := a.AddEntry(EntryInput{Name: "abcde"}); err == nil {
		t.Fatal("over-length name must be rejected")
	}
}

func TestBombRejectsNegativeSize(t *testing.T) {
	a, _ := NewArchiveBombAuditor(DefaultArchiveBombPolicy())
	if err := a.AddEntry(EntryInput{Name: "x", Compressed: -1}); err == nil {
		t.Fatal("negative compressed size must be rejected")
	}
	if err := a.AddEntry(EntryInput{Name: "y", Uncompressed: -1}); err == nil {
		t.Fatal("negative uncompressed size must be rejected")
	}
}

func TestBombZip64Gate(t *testing.T) {
	a, _ := NewArchiveBombAuditor(DefaultArchiveBombPolicy())
	if err := a.AddEntry(EntryInput{Name: "z", Compressed: 1, Uncompressed: 2, Zip64: true}); err == nil {
		t.Fatal("zip64 must be denied by default")
	}
	p := DefaultArchiveBombPolicy()
	p.AllowZip64 = true
	b, _ := NewArchiveBombAuditor(p)
	if err := b.AddEntry(EntryInput{Name: "z", Compressed: 1, Uncompressed: 2, Zip64: true}); err != nil {
		t.Fatalf("zip64 allowed policy: %v", err)
	}
}

func TestBombNestDepth(t *testing.T) {
	p := DefaultArchiveBombPolicy()
	if err := p.AssertNestDepth(0); err != nil {
		t.Fatal(err)
	}
	if err := p.AssertNestDepth(2); err != nil {
		t.Fatal(err)
	}
	if err := p.AssertNestDepth(3); err == nil {
		t.Fatal("depth beyond cap must be rejected")
	}
	if err := p.AssertNestDepth(-1); err == nil {
		t.Fatal("negative depth must be rejected")
	}
}

func TestBombDirectoryExcludedFromRatio(t *testing.T) {
	p := DefaultArchiveBombPolicy()
	p.MaxCompressionRatio = 10
	a, _ := NewArchiveBombAuditor(p)
	// 目录条目压缩字节为 0，不应触发除零或误报高压缩比。
	if err := a.AddEntry(EntryInput{Name: "d/", IsDir: true, Compressed: 0, Uncompressed: 0}); err != nil {
		t.Fatalf("directory entry: %v", err)
	}
}

func TestBombReasonDescription(t *testing.T) {
	if DescribeBombReason(BombReasonRatio) == "" {
		t.Fatal("description must not be empty")
	}
	if IsBombError(nil) {
		t.Fatal("nil must not be a bomb error")
	}
}
