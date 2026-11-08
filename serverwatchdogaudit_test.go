package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func spwWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func spwHas(findings []WatchdogFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const spwGoodSpigot = "settings:\n  restart-on-crash: true\n  restart-script: ./start.sh\n  timeout-time: 120\n"

func TestWatchdogMissingDir(t *testing.T) {
	a := AuditServerWatchdog(filepath.Join(t.TempDir(), "absent"))
	if !spwHas(a.Findings, spwReasonMissing) {
		t.Fatalf("期望 missing: %v", a.Describe())
    }
}

func TestWatchdogEmptyDir(t *testing.T) {
	a := AuditServerWatchdog(t.TempDir())
	if len(a.Findings) != 0 {
		t.Fatalf("空目录不应有发现: %v", a.Describe())
	}
}

func TestWatchdogGoodConfig(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "spigot.yml", spwGoodSpigot)
	a := AuditServerWatchdog(dir)
	if len(a.Findings) != 0 {
		t.Fatalf("合规配置不应有发现: %v", a.Describe())
	}
}

func TestWatchdogDisabledByProperty(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "server.properties", "max-tick-time=-1\n")
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonDisabled) || a.Blocking() {
		t.Fatalf("关闭看门狗应告警不阻断: %v", a.Describe())
	}
}

func TestWatchdogZeroTickTime(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "server.properties", "max-tick-time=0\n")
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonBadValue) || !a.Blocking() {
		t.Fatalf("max-tick-time=0 应阻断: %v", a.Describe())
	}
}

func TestWatchdogNonNumericTickTime(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "server.properties", "max-tick-time=abc\n")
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonBadValue) || !a.Blocking() {
		t.Fatalf("非整数应阻断: %v", a.Describe())
	}
}

func TestWatchdogTimeoutLow(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "spigot.yml", strings.Replace(spwGoodSpigot, "timeout-time: 120", "timeout-time: 10", 1))
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonLow) || a.Blocking() {
		t.Fatalf("过低超时应告警: %v", a.Describe())
	}
}

func TestWatchdogTimeoutHigh(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "spigot.yml", strings.Replace(spwGoodSpigot, "timeout-time: 120", "timeout-time: 4000", 1))
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonHigh) {
		t.Fatalf("过高超时应告警: %v", a.Describe())
    }
}

func TestWatchdogRestartWithoutScript(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "spigot.yml", "settings:\n  restart-on-crash: true\n  timeout-time: 120\n")
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonNoScript) || !a.Blocking() {
		t.Fatalf("缺重启脚本应阻断: %v", a.Describe())
	}
}

func TestWatchdogAbsoluteScript(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "spigot.yml", strings.Replace(spwGoodSpigot, "./start.sh", "/opt/start.sh", 1))
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonAbsPath) || !a.Blocking() {
		t.Fatalf("绝对路径应阻断: %v", a.Describe())
	}
}

func TestWatchdogTraversalScript(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "spigot.yml", strings.Replace(spwGoodSpigot, "./start.sh", "../../tmp/x.sh", 1))
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonTraversal) || !a.Blocking() {
		t.Fatalf("穿越片段应阻断: %v", a.Describe())
	}
}

func TestWatchdogMetaScript(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "spigot.yml", strings.Replace(spwGoodSpigot, "./start.sh", "sh -c 'id;reboot'", 1))
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonMeta) || !a.Blocking() {
		t.Fatalf("元字符应阻断: %v", a.Describe())
    }
}

func TestWatchdogRestartOff(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "spigot.yml", "settings:\n  restart-on-crash: false\n  timeout-time: 120\n")
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonRestartOff) || a.Blocking() {
		t.Fatalf("关闭重启应告警: %v", a.Describe())
	}
}

func TestWatchdogEarlyWarningOff(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "config/paper-global.yml", "watchdog:\n  early-warning-every: 0\n  early-warning-delay: 5000\n")
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonEarlyOff) || a.Blocking() {
		t.Fatalf("关闭预警应告警: %v", a.Describe())
	}
}

func TestWatchdogEarlyWarningBad(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "config/paper-global.yml", "watchdog:\n  early-warning-every: -5\n  early-warning-delay: 5000\n")
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonEarlyBad) || !a.Blocking() {
		t.Fatalf("非法预警间隔应阻断: %v", a.Describe())
	}
}

func TestWatchdogSymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "spigot.yml")
	if err := os.WriteFile(outside, []byte(spwGoodSpigot), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "spigot.yml")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonSymlink) || !a.Blocking() {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}

func TestWatchdogOversize(t *testing.T) {
	dir := t.TempDir()
	spwWriteFile(t, dir, "spigot.yml", "settings:\n  timeout-time: 120\n"+strings.Repeat("# pad\n", 90000))
	a := AuditServerWatchdog(dir)
	if !spwHas(a.Findings, spwReasonTooLarge) || !a.Blocking() {
		t.Fatalf("超大配置应阻断: %v", a.Describe())
	}
}
