package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stWrite(t *testing.T, dir, rel, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return path
}

func stHas(a StatsAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const stGoodUUID = "0123456789abcdef0123456789abcdef"

func TestStatsClean(t *testing.T) {
	dir := t.TempDir()
	stWrite(t, dir, "world/stats/"+stGoodUUID+".json", `{"stat.mineBlock":12}`, 0o600)
	a := AuditServerStats(dir)
	if a.Blocking() {
		t.Fatalf("干净统计被阻断: %s", a.Describe())
	}
	if a.Files != 1 {
		t.Fatalf("期望 1 个统计文件，得到 %d", a.Files)
	}
}

func TestStatsMissingDir(t *testing.T) {
	a := AuditServerStats(filepath.Join(t.TempDir(), "absent"))
	if !stHas(a, stReasonMissing) {
		t.Fatalf("期望 missing，得到 %s", a.Describe())
	}
}

func TestStatsSymlinkDir(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "realstats")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "world"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "world", "stats")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerStats(dir)
	if !stHas(a, stReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望 symlink 阻断，得到 %s", a.Describe())
	}
}

func TestStatsWorldWritable(t *testing.T) {
	dir := t.TempDir()
	stWrite(t, dir, "world/stats/"+stGoodUUID+".json", `{"a":1}`, 0o666)
	a := AuditServerStats(dir)
	if !stHas(a, stReasonWorldWritable) {
		t.Fatalf("期望 world-writable，得到 %s", a.Describe())
	}
}

func TestStatsTooLarge(t *testing.T) {
	dir := t.TempDir()
	body := `{"pad":"` + strings.Repeat("x", stMaxFileBytes+16) + `"}`
	stWrite(t, dir, "world/stats/"+stGoodUUID+".json", body, 0o600)
	a := AuditServerStats(dir)
	if !stHas(a, stReasonTooLarge) || !a.Blocking() {
		t.Fatalf("期望 too-large 阻断，得到 %s", a.Describe())
	}
}

func TestStatsBadFileName(t *testing.T) {
	dir := t.TempDir()
	stWrite(t, dir, "world/stats/notauuid.json", `{"a":1}`, 0o600)
	a := AuditServerStats(dir)
	if !stHas(a, stReasonBadFileName) {
		t.Fatalf("期望 bad-file-name，得到 %s", a.Describe())
	}
}

func TestStatsDeepNesting(t *testing.T) {
	dir := t.TempDir()
	body := strings.Repeat(`{"k":`, stMaxDepth+6) + "1" + strings.Repeat("}", stMaxDepth+6)
	stWrite(t, dir, "world/stats/"+stGoodUUID+".json", body, 0o600)
	a := AuditServerStats(dir)
	if !stHas(a, stReasonDeepNesting) || !a.Blocking() {
		t.Fatalf("期望 deep-nesting 阻断，得到 %s", a.Describe())
	}
}

func TestStatsMalformed(t *testing.T) {
	dir := t.TempDir()
	stWrite(t, dir, "world/stats/"+stGoodUUID+".json", `{"a":`, 0o600)
	a := AuditServerStats(dir)
	if !stHas(a, stReasonMalformedJSON) {
		t.Fatalf("期望 malformed-json，得到 %s", a.Describe())
	}
}

func TestStatsArrayTopLevel(t *testing.T) {
	dir := t.TempDir()
	stWrite(t, dir, "world/stats/"+stGoodUUID+".json", `[1,2,3]`, 0o600)
	a := AuditServerStats(dir)
	if !stHas(a, stReasonNotObject) {
		t.Fatalf("期望 not-object，得到 %s", a.Describe())
	}
}

func TestStatsDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	stWrite(t, dir, "world/stats/"+stGoodUUID+".json", `{"a":1,"a":2}`, 0o600)
	a := AuditServerStats(dir)
	if !stHas(a, stReasonDuplicateKey) {
		t.Fatalf("期望 duplicate-key，得到 %s", a.Describe())
	}
}

func TestStatsTooManyFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < stMaxFiles+4; i++ {
		name := fmt.Sprintf("%08x-0000-4000-8000-%012x.json", i, i)
		stWrite(t, dir, "world/stats/"+name, `{"a":1}`, 0o600)
	}
	a := AuditServerStats(dir)
	if !stHas(a, stReasonTooManyFiles) || !a.Blocking() {
		t.Fatalf("期望 too-many-files 阻断，得到 %s", a.Describe())
	}
}

func TestStatsNestedStatsDir(t *testing.T) {
	dir := t.TempDir()
	stWrite(t, dir, "world_nether/stats/"+stGoodUUID+".json", `{"a":1}`, 0o600)
	a := AuditServerStats(dir)
	if a.Files != 1 {
		t.Fatalf("期望读取 world_nether 统计，得到 %d", a.Files)
	}
}
