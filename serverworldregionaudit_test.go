package main

import (
	"os"
	"path/filepath"
	"testing"
)

func wrWrite(t *testing.T, dir, rel string, size int) string {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := make([]byte, size)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func wrHasReason(audit WorldRegionAudit, reason string) bool {
	for _, f := range audit.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestRegionMissingDirectoryBlocks(t *testing.T) {
	audit := AuditServerWorldRegions(filepath.Join(t.TempDir(), "absent"))
	if !audit.Blocking() {
		t.Fatal("missing server directory must block")
	}
	if !wrHasReason(audit, wrReasonMissing) {
		t.Fatal("missing reason not reported")
	}
}

func TestRegionCleanWorldPasses(t *testing.T) {
	dir := t.TempDir()
	wrWrite(t, dir, "world/region/r.0.0.mca", 16)
	wrWrite(t, dir, "world/entities/r.0.0.mca", 8)
	wrWrite(t, dir, "world/level.dat", 32)
	audit := AuditServerWorldRegions(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("unexpected findings: %s", audit.Describe())
	}
	if audit.Regions != 2 {
		t.Fatalf("expected two regions, got %d", audit.Regions)
	}
}

func TestRegionSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	target := wrWrite(t, dir, "outside.mca", 8)
	if err := os.MkdirAll(filepath.Join(dir, "world", "region"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "world", "region", "r.0.0.mca")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	audit := AuditServerWorldRegions(dir)
	if !wrHasReason(audit, wrReasonSymlink) {
		t.Fatal("region symlink not reported")
	}
}

func TestRegionWorldSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "realworld")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "world")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	audit := AuditServerWorldRegions(dir)
	if !wrHasReason(audit, wrReasonSymlink) {
		t.Fatal("world symlink not reported")
	}
}

func TestRegionShadowCopyWarns(t *testing.T) {
	dir := t.TempDir()
	wrWrite(t, dir, "world/region/r.0.0.mca_old", 8)
	audit := AuditServerWorldRegions(dir)
	if audit.Blocking() {
		t.Fatalf("shadow copy must not block: %s", audit.Describe())
	}
	if !wrHasReason(audit, wrReasonShadowRegion) {
		t.Fatal("shadow region not reported")
	}
}

func TestRegionBadNameWarns(t *testing.T) {
	dir := t.TempDir()
	wrWrite(t, dir, "world/region/chunk.mca", 8)
	audit := AuditServerWorldRegions(dir)
	if !wrHasReason(audit, wrReasonBadName) {
		t.Fatal("bad region name not reported")
	}
}

func TestRegionNestedDirWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "world", "region", "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	audit := AuditServerWorldRegions(dir)
	if !wrHasReason(audit, wrReasonUnknownDim) {
		t.Fatal("nested dir not reported")
	}
}

func TestRegionOversizedBlocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "world", "region", "r.0.0.mca")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(wrMaxRegionBytes + 1); err != nil {
		_ = f.Close()
		t.Skipf("truncate unsupported: %v", err)
	}
	_ = f.Close()
	audit := AuditServerWorldRegions(dir)
	if !wrHasReason(audit, wrReasonTooLarge) {
		t.Fatal("oversized region not reported")
	}
}

func TestRegionManyBlocks(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < wrMaxRegions+2; i++ {
		wrWrite(t, dir, filepath.Join("world", "region", "r."+itoaPJ(i)+".0.mca"), 1)
	}
	audit := AuditServerWorldRegions(dir)
	if !wrHasReason(audit, wrReasonTooMany) {
		t.Fatal("too many regions not reported")
	}
}

func TestRegionDescribeSkipsOK(t *testing.T) {
	audit := WorldRegionAudit{}
	audit.add("", wrReasonOK, "fine", false)
	if audit.Describe() != "世界区域文件未发现风险" {
		t.Fatalf("unexpected describe: %s", audit.Describe())
	}
}
