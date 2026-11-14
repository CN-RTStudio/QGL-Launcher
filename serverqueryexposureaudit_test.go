package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syqWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write props: %v", err)
	}
}

func TestQueryExposureClean(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "level-name=world\nmotd=QingLong Server\nserver-ip=127.0.0.1\nserver-port=25565\nmax-players=20\nview-distance=10\nnetwork-compression-threshold=256\n")
	a := AuditServerQueryExposure(dir)
	if a.HasWarnings() {
		t.Fatalf("合规配置不应报警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("合规配置不应阻断: %v", a.Describe())
	}
}

func TestQueryExposureLevelEscape(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "level-name=../outside\n")
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqLevelEscape) || !a.Blocking() {
		t.Fatalf("level-name 穿越应阻断: %v", a.Describe())
	}
}

func TestQueryExposureLevelDrive(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "level-name=C:\\saves\\world\n")
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqLevelEscape) {
		t.Fatalf("level-name 盘符应告警: %v", a.Describe())
	}
}

func TestQueryExposureMotdControl(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "motd=Hello\x07World\n")
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqMotdControl) {
		t.Fatalf("motd 控制字符应告警: %v", a.Describe())
	}
}

func TestQueryExposureMotdLink(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "motd=Join us at https://evil.example/\n")
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqMotdLink) {
		t.Fatalf("motd 外链应告警: %v", a.Describe())
	}
}

func TestQueryExposureWildcardIP(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "server-ip=0.0.0.0\n")
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqIPWildcard) {
		t.Fatalf("通配绑定应告警: %v", a.Describe())
	}
}

func TestQueryExposurePublicIP(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "server-ip=8.8.8.8\n")
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqIPPublic) {
		t.Fatalf("公网 IP 应告警: %v", a.Describe())
	}
}

func TestQueryExposureBadPort(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "server-port=70000\n")
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqPortInvalid) || !a.Blocking() {
		t.Fatalf("非法端口应阻断: %v", a.Describe())
	}
}

func TestQueryExposurePrivilegedPort(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "server-port=255\n")
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqPortLow) {
		t.Fatalf("特权端口应告警: %v", a.Describe())
	}
}

func TestQueryExposureAllowFlight(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "allow-flight=true\n")
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqAllowFlight) {
		t.Fatalf("allow-flight 应告警: %v", a.Describe())
	}
}

func TestQueryExposureLongViewDistance(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "view-distance=32\n")
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqViewDistance) {
		t.Fatalf("超远视距应告警: %v", a.Describe())
	}
}

func TestQueryExposureMissing(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerQueryExposure(dir)
	if !auditHasReason(a, syqMissing) {
		t.Fatalf("缺少属性文件应告警: %v", a.Describe())
	}
}

func TestQueryExposureDescribePrefix(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerQueryExposure(dir)
	text := a.Describe()
	if strings.TrimSpace(text) == "" {
		t.Fatalf("描述文本不应为空")
	}
	if a.HasWarnings() != (len(a.Findings) > 0) {
		t.Fatalf("HasWarnings 与 findings 不一致")
	}
}
