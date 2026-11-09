package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func saxHas(findings []AntiXrayFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const saxGoodConfig = `anticheat:
  anti-xray:
    enabled: true
    engine-mode: 2
    hidden-blocks:
      - copper_ore
      - diamond_ore
      - gold_ore
    replacement-blocks:
      - stone
    update-radius: 2
    lava-obscuring: true
    max-block-height: 64
`

func TestAntiXrayMissingDir(t *testing.T) {
	a := AuditServerAntiXray(filepath.Join(t.TempDir(), "absent"))
	if !saxHas(a.Findings, saxReasonMissing) {
		t.Fatalf("期望 missing: %v", a.Describe())
	}
}

func TestAntiXrayEmptyDir(t *testing.T) {
	a := AuditServerAntiXray(t.TempDir())
	if len(a.Findings) != 0 {
		t.Fatalf("空目录不应有发现: %v", a.Describe())
	}
}

func TestAntiXrayGoodConfig(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", saxGoodConfig)
	a := AuditServerAntiXray(dir)
	if len(a.Findings) != 0 {
		t.Fatalf("合规配置不应有发现: %v", a.Describe())
	}
}

func TestAntiXrayDisabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", "anticheat:\n  anti-xray:\n    enabled: false\n")
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonDisabled) {
		t.Fatalf("应识别关闭: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("关闭只应告警")
	}
}

func TestAntiXrayMissingEnabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", "anticheat:\n  anti-xray:\n    engine-mode: 2\n")
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonDisabled) {
		t.Fatalf("缺 enabled 应告警: %v", a.Describe())
	}
}

func TestAntiXrayBadMode(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", strings.Replace(saxGoodConfig, "engine-mode: 2", "engine-mode: 9", 1))
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonModeBad) || !a.Blocking() {
		t.Fatalf("非法 engine-mode 应阻断: %v", a.Describe())
	}
}

func TestAntiXrayWeakMode(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", strings.Replace(saxGoodConfig, "engine-mode: 2", "engine-mode: 1", 1))
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonModeWeak) {
		t.Fatalf("弱模式应告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("弱模式不应阻断")
	}
}

func TestAntiXrayEmptyHiddenBlocks(t *testing.T) {
	dir := t.TempDir()
	text := strings.Replace(saxGoodConfig, "    hidden-blocks:\n      - copper_ore\n      - diamond_ore\n      - gold_ore\n", "    hidden-blocks: []\n", 1)
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", text)
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonHiddenNone) || !a.Blocking() {
		t.Fatalf("空 hidden-blocks 应阻断: %v", a.Describe())
	}
}

func TestAntiXrayTooManyHiddenBlocks(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("anticheat:\n  anti-xray:\n    enabled: true\n    engine-mode: 2\n    hidden-blocks:\n")
	for i := 0; i < 80; i++ {
		b.WriteString("      - block_" + strings.Repeat("a", 3) + "\n")
	}
	b.WriteString("    replacement-blocks:\n      - stone\n")
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", b.String())
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonHiddenMany) || !a.Blocking() {
		t.Fatalf("过多条目应阻断: %v", a.Describe())
	}
}

func TestAntiXrayEmptyReplacement(t *testing.T) {
	dir := t.TempDir()
	text := strings.Replace(saxGoodConfig, "    replacement-blocks:\n      - stone\n", "    replacement-blocks: []\n", 1)
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", text)
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonReplace) || !a.Blocking() {
		t.Fatalf("空 replacement 应阻断: %v", a.Describe())
	}
}

func TestAntiXrayBadRadius(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", strings.Replace(saxGoodConfig, "update-radius: 2", "update-radius: 9", 1))
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonRadius) || !a.Blocking() {
		t.Fatalf("越界半径应阻断: %v", a.Describe())
	}
}

func TestAntiXrayBadHeight(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", strings.Replace(saxGoodConfig, "max-block-height: 64", "max-block-height: 8", 1))
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonHeight) || !a.Blocking() {
		t.Fatalf("越界高度应阻断: %v", a.Describe())
	}
}

func TestAntiXrayLavaWarning(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", strings.Replace(saxGoodConfig, "lava-obscuring: true", "lava-obscuring: false", 1))
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonLava) || a.Blocking() {
		t.Fatalf("关闭岩浆遮蔽应告警不阻断: %v", a.Describe())
	}
}

func TestAntiXraySymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "pw.yml")
	if err := os.WriteFile(outside, []byte(saxGoodConfig), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
    }
	if err := os.Symlink(outside, filepath.Join(dir, "config", "paper-world-defaults.yml")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonSymlink) || !a.Blocking() {
		t.Fatalf("符号链接配置应阻断: %v", a.Describe())
	}
}

func TestAntiXrayOversize(t *testing.T) {
	dir := t.TempDir()
	big := "anticheat:\n  anti-xray:\n    enabled: true\n" + strings.Repeat("# padding\n", 60000)
	auditWriteFile(t, dir, "config/paper-world-defaults.yml", big)
	a := AuditServerAntiXray(dir)
	if !saxHas(a.Findings, saxReasonTooLarge) || !a.Blocking() {
		t.Fatalf("超大配置应阻断: %v", a.Describe())
	}
}

func TestAntiXrayListParserStops(t *testing.T) {
	items := saxListItems("a:\n  hidden-blocks:\n    - one\n    - two\n  other:\n    - three\n", "hidden-blocks")
	if len(items) != 2 || items[0] != "one" || items[1] != "two" {
		t.Fatalf("列表解析错误: %v", items)
    }
}
