package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func spdWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func spdHas(findings []DynmapFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const spdGoodConfig = "webserver-port: 8123\nwebserver-bindaddress: 127.0.0.1\nwebserver-allow-symlinks: false\ncors-allow-origin: https://example.com\ntilespath: web/tiles\n"

func TestDynmapMissingDir(t *testing.T) {
	a := AuditServerDynmap(filepath.Join(t.TempDir(), "absent"))
	if !spdHas(a.Findings, spdReasonMissing) {
		t.Fatalf("期望 missing: %v", a.Describe())
	}
}

func TestDynmapNoConfig(t *testing.T) {
	a := AuditServerDynmap(t.TempDir())
	if len(a.Findings) != 0 {
		t.Fatalf("无配置不应有发现: %v", a.Describe())
	}
}

func TestDynmapGoodConfig(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", spdGoodConfig)
	a := AuditServerDynmap(dir)
	if len(a.Findings) != 0 {
		t.Fatalf("合规配置不应有发现: %v", a.Describe())
	}
}

func TestDynmapDisabled(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", "disable-webserver: true\nwebserver-port: 80\n")
	a := AuditServerDynmap(dir)
	if len(a.Findings) != 0 {
		t.Fatalf("停用网页服务不应告警: %v", a.Describe())
	}
}

func TestDynmapBadPort(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", strings.Replace(spdGoodConfig, "8123", "70000", 1))
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonPort) || !a.Blocking() {
		t.Fatalf("非法端口应阻断: %v", a.Describe())
	}
}

func TestDynmapPrivilegedPort(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", strings.Replace(spdGoodConfig, "8123", "80", 1))
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonPortPriv) || !a.Blocking() {
		t.Fatalf("特权端口应阻断: %v", a.Describe())
	}
}

func TestDynmapPortConflict(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "server.properties", "server-port=8123\n")
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", spdGoodConfig)
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonPortClash) || !a.Blocking() {
		t.Fatalf("端口冲突应阻断: %v", a.Describe())
	}
}

func TestDynmapBindAll(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", strings.Replace(spdGoodConfig, "127.0.0.1", "0.0.0.0", 1))
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonBindAll) || a.Blocking() {
		t.Fatalf("全网卡绑定应告警: %v", a.Describe())
	}
}

func TestDynmapSymlinks(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", strings.Replace(spdGoodConfig, "webserver-allow-symlinks: false", "webserver-allow-symlinks: true", 1))
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonSymlinks) || !a.Blocking() {
		t.Fatalf("允许符号链接应阻断: %v", a.Describe())
	}
}

func TestDynmapCORSWildcard(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", strings.Replace(spdGoodConfig, "https://example.com", "*", 1))
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonCORS) || !a.Blocking() {
		t.Fatalf("CORS 通配应阻断: %v", a.Describe())
	}
}

func TestDynmapCDNInsecure(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", spdGoodConfig+"use-cdn: true\ncdn-url: http://cdn.example.com\n")
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonCDN) || !a.Blocking() {
		t.Fatalf("明文 CDN 应阻断: %v", a.Describe())
	}
}

func TestDynmapTilePathTraversal(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", strings.Replace(spdGoodConfig, "web/tiles", "../../tmp/tiles", 1))
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonTilePath) || !a.Blocking() {
		t.Fatalf("瓦片路径穿越应阻断: %v", a.Describe())
	}
}

func TestDynmapEmptyFile(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", "\n")
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonBadValue) {
		t.Fatalf("空配置应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("空配置不应阻断")
	}
}

func TestDynmapSymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "conf.txt")
	if err := os.WriteFile(outside, []byte(spdGoodConfig), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "plugins", "dynmap"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "plugins", "dynmap", "configuration.txt")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonSymlink) || !a.Blocking() {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}

func TestDynmapOversize(t *testing.T) {
	dir := t.TempDir()
	spdWriteFile(t, dir, "plugins/dynmap/configuration.txt", spdGoodConfig+strings.Repeat("# pad\n", 60000))
	a := AuditServerDynmap(dir)
	if !spdHas(a.Findings, spdReasonTooLarge) || !a.Blocking() {
		t.Fatalf("超大配置应阻断: %v", a.Describe())
	}
}
