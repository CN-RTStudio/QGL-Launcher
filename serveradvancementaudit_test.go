package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func adHas(a AdvancementAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const adGoodUUID = "0123456789abcdef0123456789abcdef"

func TestAdvancementClean(t *testing.T) {
	dir := t.TempDir()
	body := `{"criteria":{"tick":{"trigger":"minecraft:tick"}},"display":{"icon":{"id":"minecraft:stone"}}}`
	auditWriteFileMode(t, dir, "world/advancements/"+adGoodUUID+".json", body, 0o600)
	a := AuditServerAdvancements(dir)
	if a.Blocking() {
		t.Fatalf("干净进度被阻断: %s", a.Describe())
	}
}

func TestAdvancementMissingDir(t *testing.T) {
	a := AuditServerAdvancements(filepath.Join(t.TempDir(), "absent"))
	if !adHas(a, adReasonMissing) {
		t.Fatalf("期望 missing，得到 %s", a.Describe())
	}
}

func TestAdvancementSymlinkDir(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "realadv")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "world"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "world", "advancements")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望 symlink 阻断，得到 %s", a.Describe())
	}
}

func TestAdvancementWorldWritable(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "world/advancements/"+adGoodUUID+".json", `{"criteria":{}}`, 0o666)
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonWorldWritable) {
		t.Fatalf("期望 world-writable，得到 %s", a.Describe())
	}
}

func TestAdvancementTooLarge(t *testing.T) {
	dir := t.TempDir()
	body := `{"pad":"` + strings.Repeat("x", adMaxFileBytes+16) + `"}`
	auditWriteFileMode(t, dir, "world/advancements/"+adGoodUUID+".json", body, 0o600)
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonTooLarge) || !a.Blocking() {
		t.Fatalf("期望 too-large 阻断，得到 %s", a.Describe())
	}
}

func TestAdvancementBadFileName(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "world/advancements/legacy.json", `{"criteria":{}}`, 0o600)
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonBadFileName) {
		t.Fatalf("期望 bad-file-name，得到 %s", a.Describe())
	}
}

func TestAdvancementDeepNesting(t *testing.T) {
	dir := t.TempDir()
	body := strings.Repeat(`{"k":`, adMaxDepth+6) + "1" + strings.Repeat("}", adMaxDepth+6)
	auditWriteFileMode(t, dir, "world/advancements/"+adGoodUUID+".json", body, 0o600)
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonDeepNesting) || !a.Blocking() {
		t.Fatalf("期望 deep-nesting 阻断，得到 %s", a.Describe())
	}
}

func TestAdvancementMalformed(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "world/advancements/"+adGoodUUID+".json", `{"criteria":`, 0o600)
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonMalformedJSON) {
		t.Fatalf("期望 malformed-json，得到 %s", a.Describe())
	}
}

func TestAdvancementLootTraversal(t *testing.T) {
	dir := t.TempDir()
	body := `{"criteria":{"a":{"trigger":"minecraft:tick"}},"rewards":{"loot":["../../secrets/treasure"]}}`
	auditWriteFileMode(t, dir, "world/advancements/"+adGoodUUID+".json", body, 0o600)
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonLootTraversal) || !a.Blocking() {
		t.Fatalf("期望 loot-traversal 阻断，得到 %s", a.Describe())
	}
}

func TestAdvancementIconTraversal(t *testing.T) {
	dir := t.TempDir()
	body := `{"criteria":{},"display":{"icon":"../outside/icon.png"}}`
	auditWriteFileMode(t, dir, "world/advancements/"+adGoodUUID+".json", body, 0o600)
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonIconTraversal) {
		t.Fatalf("期望 icon-traversal，得到 %s", a.Describe())
	}
}

func TestAdvancementParentEscape(t *testing.T) {
	dir := t.TempDir()
	body := `{"criteria":{},"parent":"../../../tmp/evil"}`
	auditWriteFileMode(t, dir, "world/advancements/"+adGoodUUID+".json", body, 0o600)
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonParentEscape) {
		t.Fatalf("期望 parent-escape，得到 %s", a.Describe())
	}
}

func TestAdvancementDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "world/advancements/"+adGoodUUID+".json", `{"criteria":{},"criteria":{}}`, 0o600)
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonDuplicateKey) {
		t.Fatalf("期望 duplicate-key，得到 %s", a.Describe())
	}
}

func TestAdvancementTooManyCriteria(t *testing.T) {
	dir := t.TempDir()
	var body strings.Builder
	body.WriteString(`{"criteria":{`)
	for i := 0; i < adMaxCriteria+6; i++ {
		if i > 0 {
			body.WriteString(",")
		}
		body.WriteString(fmt.Sprintf(`"c%03d":{"trigger":"minecraft:tick"}`, i))
	}
	body.WriteString("}}")
	auditWriteFileMode(t, dir, "world/advancements/"+adGoodUUID+".json", body.String(), 0o600)
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonTooManyCriteria) {
		t.Fatalf("期望 too-many-criteria，得到 %s", a.Describe())
	}
}

func TestAdvancementTooManyFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < adMaxFiles+4; i++ {
		name := fmt.Sprintf("%08x-0000-4000-8000-%012x.json", i, i)
		auditWriteFileMode(t, dir, "world/advancements/"+name, `{"criteria":{"tick":{"trigger":"minecraft:tick"}}}`, 0o600)
	}
	a := AuditServerAdvancements(dir)
	if !adHas(a, adReasonTooManyFiles) || !a.Blocking() {
		t.Fatalf("期望 too-many-files 阻断，得到 %s", a.Describe())
	}
}
