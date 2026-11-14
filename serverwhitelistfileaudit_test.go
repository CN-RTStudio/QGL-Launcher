package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func swfHas(findings []WhitelistFileFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestWhitelistMissingFile(t *testing.T) {
	a := AuditServerWhitelistFile(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少白名单不应报警: %v", a.Describe())
	}
}

func TestWhitelistClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "whitelist.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch"}]`)
	a := AuditServerWhitelistFile(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合法白名单不应报警: %v", a.Describe())
	}
}

func TestWhitelistInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "whitelist.json", `{bad`)
	a := AuditServerWhitelistFile(dir)
	if !a.Blocking() || !swfHas(a.Findings, swfReasonShape) {
		t.Fatalf("非法 JSON 应阻断: %v", a.Describe())
	}
}

func TestWhitelistBadUUID(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "whitelist.json", `[{"uuid":"not-a-uuid","name":"Notch"}]`)
	a := AuditServerWhitelistFile(dir)
	if !a.Blocking() || !swfHas(a.Findings, swfReasonUUID) {
		t.Fatalf("非法 uuid 应阻断: %v", a.Describe())
	}
}

func TestWhitelistBadName(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "whitelist.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"<script>"}]`)
	a := AuditServerWhitelistFile(dir)
	if !a.Blocking() || !swfHas(a.Findings, swfReasonName) {
		t.Fatalf("非法玩家名应阻断: %v", a.Describe())
	}
}

func TestWhitelistControlChars(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "whitelist.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Not\nch"}]`)
	a := AuditServerWhitelistFile(dir)
	if !a.Blocking() || !swfHas(a.Findings, swfReasonCtl) {
		t.Fatalf("控制字符应阻断: %v", a.Describe())
	}
}

func TestWhitelistEmpty(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "whitelist.json", `[]`)
	a := AuditServerWhitelistFile(dir)
	if a.Blocking() || !swfHas(a.Findings, swfReasonEmpty) {
		t.Fatalf("空白名单应告警: %v", a.Describe())
	}
}

func TestWhitelistDuplicate(t *testing.T) {
	dir := t.TempDir()
	entry := `{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch"}`
	auditWriteFile(t, dir, "whitelist.json", "["+entry+","+entry+"]")
	a := AuditServerWhitelistFile(dir)
	if a.Blocking() || !swfHas(a.Findings, swfReasonDup) {
		t.Fatalf("重复条目应告警: %v", a.Describe())
	}
}

func TestWhitelistTooMany(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 520; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch"}`)
	}
	b.WriteString("]")
	auditWriteFile(t, dir, "whitelist.json", b.String())
	a := AuditServerWhitelistFile(dir)
	if !a.Blocking() || !swfHas(a.Findings, swfReasonMany) {
		t.Fatalf("条目超限应阻断: %v", a.Describe())
	}
}

func TestWhitelistSymlink(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "target.json", `[]`)
	link := filepath.Join(dir, "whitelist.json")
	if err := os.Symlink(filepath.Join(dir, "target.json"), link); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerWhitelistFile(dir)
	if !a.Blocking() || !swfHas(a.Findings, swfReasonLink) {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}
