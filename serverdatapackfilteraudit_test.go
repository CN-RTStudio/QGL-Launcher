package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pfWrite(t *testing.T, dir, rel, body string, mode os.FileMode) string {
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

func pfHas(a PackFilterAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPackFilterClean(t *testing.T) {
	dir := t.TempDir()
	body := `{"pack":{"pack_format":48,"description":"demo","filter":{"block":[{"namespace":"minecraft","path":"advancement/demo"}]}}}`
	pfWrite(t, dir, "datapacks/demo/pack.mcmeta", body, 0o600)
	a := AuditServerDataPackFilters(dir)
	if a.Blocking() {
		t.Fatalf("干净数据包被阻断: %s", a.Describe())
	}
	if a.Packs != 1 {
		t.Fatalf("期望 1 个数据包，得到 %d", a.Packs)
	}
}

func TestPackFilterMissingServer(t *testing.T) {
	a := AuditServerDataPackFilters(filepath.Join(t.TempDir(), "absent"))
	if !pfHas(a, pfReasonMissing) {
		t.Fatalf("期望 missing，得到 %s", a.Describe())
	}
}

func TestPackFilterMissingMeta(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "datapacks", "empty"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonMissing) {
		t.Fatalf("期望 missing，得到 %s", a.Describe())
	}
}

func TestPackFilterSymlinkMeta(t *testing.T) {
	dir := t.TempDir()
	real := pfWrite(t, dir, "real.mcmeta", `{"pack":{"pack_format":48}}`, 0o600)
	if err := os.MkdirAll(filepath.Join(dir, "datapacks", "linked"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "datapacks", "linked", "pack.mcmeta")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望 symlink 阻断，得到 %s", a.Describe())
	}
}

func TestPackFilterWorldWritable(t *testing.T) {
	dir := t.TempDir()
	pfWrite(t, dir, "datapacks/open/pack.mcmeta", `{"pack":{"pack_format":48}}`, 0o666)
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonWorldWritable) {
		t.Fatalf("期望 world-writable，得到 %s", a.Describe())
	}
}

func TestPackFilterTooLarge(t *testing.T) {
	dir := t.TempDir()
	body := `{"pack":{"pack_format":48,"description":"` + strings.Repeat("x", pfMaxFileBytes+16) + `"}}`
	pfWrite(t, dir, "datapacks/big/pack.mcmeta", body, 0o600)
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonTooLarge) || !a.Blocking() {
		t.Fatalf("期望 too-large 阻断，得到 %s", a.Describe())
	}
}

func TestPackFilterCoversAll(t *testing.T) {
	dir := t.TempDir()
	body := `{"pack":{"pack_format":48,"filter":{"block":[{"namespace":"*","path":"*"}]}}}`
	pfWrite(t, dir, "datapacks/dark/pack.mcmeta", body, 0o600)
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonFilterAll) || !a.Blocking() {
		t.Fatalf("期望 filter-covers-all 阻断，得到 %s", a.Describe())
	}
}

func TestPackFilterEmptyNamespace(t *testing.T) {
	dir := t.TempDir()
	body := `{"pack":{"pack_format":48,"filter":{"block":[{"namespace":"","path":"tags"}]}}}`
	pfWrite(t, dir, "datapacks/blank/pack.mcmeta", body, 0o600)
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonEmptyNamespace) || !a.Blocking() {
		t.Fatalf("期望 empty-namespace 阻断，得到 %s", a.Describe())
	}
}

func TestPackFilterPathEscape(t *testing.T) {
	dir := t.TempDir()
	body := `{"pack":{"pack_format":48,"filter":{"block":[{"namespace":"minecraft","path":"../../secrets"}]}}}`
	pfWrite(t, dir, "datapacks/escape/pack.mcmeta", body, 0o600)
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonPathEscape) || !a.Blocking() {
		t.Fatalf("期望 path-escape 阻断，得到 %s", a.Describe())
	}
}

func TestPackFilterWildcardNs(t *testing.T) {
	dir := t.TempDir()
	body := `{"pack":{"pack_format":48,"filter":{"block":[{"namespace":"*","path":"recipes"}]}}}`
	pfWrite(t, dir, "datapacks/wild/pack.mcmeta", body, 0o600)
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonBadPattern) {
		t.Fatalf("期望 bad-pattern，得到 %s", a.Describe())
	}
}

func TestPackFilterDuplicate(t *testing.T) {
	dir := t.TempDir()
	body := `{"pack":{"pack_format":48,"filter":{"block":[` +
		`{"namespace":"minecraft","path":"tags"},` +
		`{"namespace":"minecraft","path":"tags"}]}}}`
	pfWrite(t, dir, "datapacks/dup/pack.mcmeta", body, 0o600)
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonDuplicateFilter) {
		t.Fatalf("期望 duplicate-filter，得到 %s", a.Describe())
	}
}

func TestPackFilterTooMany(t *testing.T) {
	dir := t.TempDir()
	var body strings.Builder
	body.WriteString(`{"pack":{"pack_format":48,"filter":{"block":[`)
	for i := 0; i < pfMaxFilters+4; i++ {
		if i > 0 {
			body.WriteString(",")
		}
		body.WriteString(`{"namespace":"minecraft","path":"p`)
		body.WriteString(string(rune('a' + i%26)))
		body.WriteString(`"}`)
	}
	body.WriteString("]}}}")
	pfWrite(t, dir, "datapacks/many/pack.mcmeta", body.String(), 0o600)
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonTooManyFilters) || !a.Blocking() {
		t.Fatalf("期望 too-many-filters 阻断，得到 %s", a.Describe())
	}
}

func TestPackFilterMalformed(t *testing.T) {
	dir := t.TempDir()
	pfWrite(t, dir, "datapacks/broken/pack.mcmeta", `{"pack":`, 0o600)
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonMalformedJSON) {
		t.Fatalf("期望 malformed-json，得到 %s", a.Describe())
	}
}

func TestPackFilterWeakFormat(t *testing.T) {
	dir := t.TempDir()
	pfWrite(t, dir, "datapacks/old/pack.mcmeta", `{"pack":{"description":"legacy"}}`, 0o600)
	a := AuditServerDataPackFilters(dir)
	if !pfHas(a, pfReasonWeakFormat) {
		t.Fatalf("期望 weak-pack-format，得到 %s", a.Describe())
	}
}

func TestPackFilterWorldVariant(t *testing.T) {
	dir := t.TempDir()
	body := `{"pack":{"pack_format":48,"filter":{"block":[{"namespace":"minecraft","path":"tags"}]}}}`
	pfWrite(t, dir, "world/datapacks/local/pack.mcmeta", body, 0o600)
	a := AuditServerDataPackFilters(dir)
	if a.Packs != 1 {
		t.Fatalf("期望读取 world/datapacks，得到 %d", a.Packs)
	}
}
