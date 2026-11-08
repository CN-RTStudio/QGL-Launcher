package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func spxWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func spxHas(a *PropDupAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPropertiesStructureClean(t *testing.T) {
	dir := t.TempDir()
	spxWrite(t, dir, "# comment\nonline-mode=true\nmotd=hello\nserver-port=25565\n")
	a := AuditServerPropertiesStructure(dir)
	if a.HasWarnings() {
		t.Fatalf("干净属性文件不应报警: %v", a.Describe())
	}
	if a.Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}

func TestPropertiesStructureMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerPropertiesStructure(dir)
	if !spxHas(a, spxMiss) {
		t.Fatalf("缺少文件应记录: %v", a.Describe())
	}
}

func TestPropertiesStructureDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	spxWrite(t, dir, "online-mode=true\nonline-mode=false\n")
	a := AuditServerPropertiesStructure(dir)
	if !spxHas(a, spxDupKey) {
		t.Fatalf("重复键应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("重复键应阻断: %v", a.Describe())
	}
}

func TestPropertiesStructureCaseDuplicate(t *testing.T) {
	dir := t.TempDir()
	spxWrite(t, dir, "Online-Mode=true\nonline-mode=false\n")
	a := AuditServerPropertiesStructure(dir)
	if !spxHas(a, spxCaseDup) {
		t.Fatalf("大小写重复应记录: %v", a.Describe())
	}
}

func TestPropertiesStructureEmptyKey(t *testing.T) {
	dir := t.TempDir()
	spxWrite(t, dir, "=value\nonline-mode=true\n")
	a := AuditServerPropertiesStructure(dir)
	if !spxHas(a, spxEmptyKey) {
		t.Fatalf("空键应记录: %v", a.Describe())
	}
}

func TestPropertiesStructureMalformedLine(t *testing.T) {
	dir := t.TempDir()
	spxWrite(t, dir, "online-mode=true\nthis line has no equals\n")
	a := AuditServerPropertiesStructure(dir)
	if !spxHas(a, spxMalformed) {
		t.Fatalf("缺等号行应记录: %v", a.Describe())
	}
}

func TestPropertiesStructureKeyWhitespace(t *testing.T) {
	dir := t.TempDir()
	spxWrite(t, dir, " online-mode =true\n")
	a := AuditServerPropertiesStructure(dir)
	if !spxHas(a, spxKeySpace) {
		t.Fatalf("键空白应记录: %v", a.Describe())
	}
}

func TestPropertiesStructureInlineHash(t *testing.T) {
	dir := t.TempDir()
	spxWrite(t, dir, "motd=hello # not a comment\n")
	a := AuditServerPropertiesStructure(dir)
	if !spxHas(a, spxInlineHash) {
		t.Fatalf("值内 # 应记录: %v", a.Describe())
	}
}

func TestPropertiesStructureLongValue(t *testing.T) {
	dir := t.TempDir()
	spxWrite(t, dir, "motd="+strings.Repeat("b", 2049)+"\n")
	a := AuditServerPropertiesStructure(dir)
	if !spxHas(a, spxLongValue) {
		t.Fatalf("超长值应记录: %v", a.Describe())
	}
}

func TestPropertiesStructureTooManyKeys(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < spxMaxKeys+3; i++ {
		b.WriteString(fmt.Sprintf("key-%d=value\n", i))
	}
	spxWrite(t, dir, b.String())
	a := AuditServerPropertiesStructure(dir)
	if !spxHas(a, spxTooManyKeys) {
		t.Fatalf("键过多应记录: %v", a.Describe())
	}
}

func TestPropertiesStructureEmptyFile(t *testing.T) {
	dir := t.TempDir()
	spxWrite(t, dir, "\n# only comments\n")
	a := AuditServerPropertiesStructure(dir)
	if !spxHas(a, spxEmpty) {
		t.Fatalf("无有效键应记录: %v", a.Describe())
	}
}

func TestPropertiesStructureEmptyServerDir(t *testing.T) {
	a := AuditServerPropertiesStructure("")
	if !spxHas(a, spxMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
	if len(a.Findings) != 1 {
		t.Fatalf("空目录只应产生一条记录: %d", len(a.Findings))
	}
}
