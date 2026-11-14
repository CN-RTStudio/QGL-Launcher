package main

import (
	"os"
	"path/filepath"
	"testing"
)


func sbmHas(findings []BlueMapFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const sbmGoodWeb = "enabled: true\nwebserver {\n  ip: \"127.0.0.1\"\n  port: 8100\n  max-connection-per-second: 25\n}\n"
const sbmGoodCore = "accept-download: false\nmetrics: false\ndata: \"bluemap\"\n"

func TestBlueMapMissingDir(t *testing.T) {
	a := AuditServerBlueMap(filepath.Join(t.TempDir(), "absent"))
	if !sbmHas(a.Findings, sbmReasonMissing) {
		t.Fatalf("期望 missing: %v", a.Describe())
	}
}

func TestBlueMapClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "server-port=25565\n")
	auditWriteFile(t, dir, "plugins/BlueMap/webserver.conf", sbmGoodWeb)
	auditWriteFile(t, dir, "plugins/BlueMap/core.conf", sbmGoodCore)
	a := AuditServerBlueMap(dir)
	if a.HasWarnings() {
		t.Fatalf("不应有发现: %v", a.Describe())
	}
}

func TestBlueMapPortInvalid(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "server-port=25565\n")
	auditWriteFile(t, dir, "plugins/BlueMap/webserver.conf", "enabled: true\nwebserver {\n ip: \"127.0.0.1\"\n port: 99999\n}\n")
	auditWriteFile(t, dir, "plugins/BlueMap/core.conf", sbmGoodCore)
	a := AuditServerBlueMap(dir)
	if !sbmHas(a.Findings, sbmReasonPort) || !a.Blocking() {
		t.Fatalf("期望端口非法阻断: %v", a.Describe())
	}
}

func TestBlueMapPortConflict(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "server-port=8100\n")
	auditWriteFile(t, dir, "plugins/BlueMap/webserver.conf", sbmGoodWeb)
	auditWriteFile(t, dir, "plugins/BlueMap/core.conf", sbmGoodCore)
	a := AuditServerBlueMap(dir)
	if !sbmHas(a.Findings, sbmReasonPortClash) || !a.Blocking() {
		t.Fatalf("期望端口冲突: %v", a.Describe())
	}
}

func TestBlueMapBindAll(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "plugins/BlueMap/webserver.conf", "enabled: true\nwebserver {\n ip: \"0.0.0.0\"\n port: 8100\n}\n")
	auditWriteFile(t, dir, "plugins/BlueMap/core.conf", sbmGoodCore)
	a := AuditServerBlueMap(dir)
	if !sbmHas(a.Findings, sbmReasonBindAll) {
		t.Fatalf("期望绑定全部网卡: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("绑定告警不应阻断")
	}
}

func TestBlueMapAcceptDownload(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "plugins/BlueMap/webserver.conf", sbmGoodWeb)
	auditWriteFile(t, dir, "plugins/BlueMap/core.conf", "accept-download: true\nmetrics: true\ndata: \"bluemap\"\n")
	a := AuditServerBlueMap(dir)
	if !sbmHas(a.Findings, sbmReasonDownload) || !sbmHas(a.Findings, sbmReasonMetrics) {
		t.Fatalf("期望下载与统计告警: %v", a.Describe())
	}
}

func TestBlueMapDataEscape(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "plugins/BlueMap/webserver.conf", sbmGoodWeb)
	auditWriteFile(t, dir, "plugins/BlueMap/core.conf", "data: \"../../outside\"\n")
	a := AuditServerBlueMap(dir)
	if !sbmHas(a.Findings, sbmReasonDataPath) || !a.Blocking() {
		t.Fatalf("期望数据目录越界阻断: %v", a.Describe())
	}
}

func TestBlueMapRateDisabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "plugins/BlueMap/webserver.conf", "enabled: true\nwebserver {\n ip: \"127.0.0.1\"\n port: 8100\n max-connection-per-second: 0\n}\n")
	auditWriteFile(t, dir, "plugins/BlueMap/core.conf", sbmGoodCore)
	a := AuditServerBlueMap(dir)
	if !sbmHas(a.Findings, sbmReasonRate) || !a.Blocking() {
		t.Fatalf("期望限流关闭阻断: %v", a.Describe())
	}
}

func TestBlueMapSymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "outside.conf")
	if err := os.WriteFile(real, []byte(sbmGoodWeb), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	target := filepath.Join(dir, "plugins/BlueMap/webserver.conf")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(real, target); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerBlueMap(dir)
	if !sbmHas(a.Findings, sbmReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望符号链接阻断: %v", a.Describe())
	}
}
