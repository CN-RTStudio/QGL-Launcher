package main

import (
	"strings"
	"testing"
)

func TestMotdControlClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "motd=A Minecraft Server\nonline-mode=true\n")
	a := AuditServerMotdControl(dir)
	if a.HasWarnings() {
		t.Fatalf("干净 MOTD 不应报警: %v", a.Describe())
	}
	if a.Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}

func TestMotdControlMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerMotdControl(dir)
	if !auditHasReason(a, smcMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("缺少文件不应阻断: %v", a.Describe())
	}
}

func TestMotdControlEmptyMotd(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "motd=\nonline-mode=true\n")
	a := AuditServerMotdControl(dir)
	if !auditHasReason(a, smcEmpty) {
		t.Fatalf("空 MOTD 应记录: %v", a.Describe())
	}
}

func TestMotdControlRejectsControlCharacter(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "motd=hello\u0007world\n")
	a := AuditServerMotdControl(dir)
	if !auditHasReason(a, smcControl) {
		t.Fatalf("控制字符应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("控制字符应阻断: %v", a.Describe())
	}
}

func TestMotdControlRejectsBidiOverride(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "motd=admin\u202egnp.txt\n")
	a := AuditServerMotdControl(dir)
	if !auditHasReason(a, smcBidi) {
		t.Fatalf("双向控制字符应记录: %v", a.Describe())
	}
}

func TestMotdControlRejectsZeroWidth(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "motd=vis\u200bible\n")
	a := AuditServerMotdControl(dir)
	if !auditHasReason(a, smcZeroWidth) {
		t.Fatalf("零宽字符应记录: %v", a.Describe())
	}
}

func TestMotdControlRejectsLongMotd(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "motd="+strings.Repeat("a", smcMaxRunes+1)+"\n")
	a := AuditServerMotdControl(dir)
	if !auditHasReason(a, smcTooLong) {
		t.Fatalf("超长 MOTD 应记录: %v", a.Describe())
	}
}

func TestMotdControlRejectsDenseSectionCodes(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "motd="+strings.Repeat("§a", smcMaxSection+2)+"\n")
	a := AuditServerMotdControl(dir)
	if !auditHasReason(a, smcSectionDense) {
		t.Fatalf("格式码过密应记录: %v", a.Describe())
	}
}

func TestMotdControlRejectsInvalidSectionCode(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "motd=hello §z world\n")
	a := AuditServerMotdControl(dir)
	if !auditHasReason(a, smcSection) {
		t.Fatalf("非法格式码应记录: %v", a.Describe())
	}
}

func TestMotdControlRejectsMalformedLine(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "online-mode=true\nnot a property line\nmotd=ok\n")
	a := AuditServerMotdControl(dir)
	if !auditHasReason(a, smcMalformed) {
		t.Fatalf("畸形行应记录: %v", a.Describe())
	}
}

func TestMotdControlRejectsKeyWhitespace(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, " motd = spaced\n")
	a := AuditServerMotdControl(dir)
	if !auditHasReason(a, smcKeySpace) {
		t.Fatalf("键首尾空白应记录: %v", a.Describe())
	}
}

func TestMotdControlEmptyServerDir(t *testing.T) {
	a := AuditServerMotdControl("")
	if !auditHasReason(a, smcMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
	if len(a.Findings) != 1 {
		t.Fatalf("空目录只应产生一条记录: %d", len(a.Findings))
	}
}
