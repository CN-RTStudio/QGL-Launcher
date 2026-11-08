package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	saxMaxFindings      = 40
	saxMaxYAML          = 512 * 1024
	saxMaxHiddenBlocks  = 64
	saxMaxRadius        = 4
	saxMinBlockHeight   = 16
	saxMaxBlockHeight   = 384
	saxReasonOK         = "ok"
	saxReasonMissing    = "missing"
	saxReasonSymlink    = "symlink"
	saxReasonTooLarge   = "too-large"
	saxReasonUnreadable = "unreadable"
	saxReasonDisabled   = "anti-xray-disabled"
	saxReasonModeWeak   = "engine-mode-weak"
	saxReasonModeBad    = "engine-mode-invalid"
	saxReasonHiddenNone = "hidden-blocks-empty"
	saxReasonHiddenMany = "hidden-blocks-too-many"
	saxReasonReplace    = "replacement-blocks-empty"
	saxReasonRadius     = "update-radius-out-of-range"
	saxReasonHeight     = "max-block-height-out-of-range"
	saxReasonLava       = "lava-obscuring-disabled"
	saxReasonListBad    = "list-entry-invalid"
)

type AntiXrayFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type AntiXrayAudit struct {
	ServerDir string
	Findings  []AntiXrayFinding
}

func (a *AntiXrayAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= saxMaxFindings {
		return
	}
	a.Findings = append(a.Findings, AntiXrayFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *AntiXrayAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *AntiXrayAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *AntiXrayAudit) Describe() string {
	return describeAuditFindings("反矿透配置未发现风险", a.Findings, 12,
		func(f AntiXrayFinding) []string {
			return []string{f.File, f.Reason}
		},
		func(f AntiXrayFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func saxLoadText(a *AntiXrayAudit, root, rel string, maxBytes int64) (string, bool) {
	path := filepath.Join(root, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, saxReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return "", false
	}
	data, err := readBoundedFile(path, maxBytes)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return "", false
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, saxReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", maxBytes), true)
			return "", false
		}
		a.add(rel, saxReasonUnreadable, "配置文件不可读", false)
		return "", false
	}
	return string(data), true
}

func saxIndent(line string) int {
	count := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

func saxListItems(text, key string) []string {
	lines := strings.Split(text, "\n")
	items := []string{}
	found := -1
	baseIndent := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if found < 0 {
			colon := strings.Index(trimmed, ":")
			if colon < 0 {
				continue
			}
			name := strings.TrimSpace(trimmed[:colon])
			if name != key {
				continue
			}
			rest := strings.TrimSpace(trimmed[colon+1:])
			if rest != "" && rest != "[]" {
				continue
			}
			found = i
			baseIndent = saxIndent(line)
			continue
		}
		if saxIndent(line) <= baseIndent {
			break
		}
		if !strings.HasPrefix(trimmed, "- ") {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		items = append(items, cfgStripQuotes(item))
		if len(items) > 256 {
			break
		}
	}
	return items
}

func saxBool(flat map[string]string, path string) (bool, bool) {
	value, ok := cfgLookup(flat, path)
	if !ok {
		return false, false
	}
	switch strings.ToLower(cfgStripQuotes(value)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	default:
		return false, false
	}
}

func AuditServerAntiXray(serverDir string) *AntiXrayAudit {
	a := &AntiXrayAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", saxReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", saxReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", saxReasonMissing, "服务器目录不存在", false)
		return a
	}

	text, ok := saxLoadText(a, serverDir, "config/paper-world-defaults.yml", saxMaxYAML)
	if !ok {
		return a
	}
	flat := cfgFlattenYAML(text)

	enabled, hasEnabled := saxBool(flat, "anticheat.anti-xray.enabled")
	if !hasEnabled {
		a.add("config/paper-world-defaults.yml", saxReasonDisabled, "未声明 anti-xray.enabled", false)
		return a
	}
	if !enabled {
		a.add("config/paper-world-defaults.yml", saxReasonDisabled, "anti-xray 已关闭", false)
		return a
	}

	modeText, found := cfgLookup(flat, "anticheat.anti-xray.engine-mode")
	if !found {
		a.add("config/paper-world-defaults.yml", saxReasonModeBad, "缺少 engine-mode", true)
	} else if mode, parsed := cfgParseInt(cfgStripQuotes(modeText)); !parsed || mode < 1 || mode > 3 {
		a.add("config/paper-world-defaults.yml", saxReasonModeBad, "engine-mode 取值非法", true)
	} else if mode == 1 {
		a.add("config/paper-world-defaults.yml", saxReasonModeWeak, "engine-mode=1 仅替换方块，易被统计推断", false)
	}

	hidden := saxListItems(text, "hidden-blocks")
	if len(hidden) == 0 {
		a.add("config/paper-world-defaults.yml", saxReasonHiddenNone, "hidden-blocks 未配置实体方块", true)
	} else {
		if len(hidden) > saxMaxHiddenBlocks {
			a.add("config/paper-world-defaults.yml", saxReasonHiddenMany,
				fmt.Sprintf("hidden-blocks 条目 %d 超过上限 %d", len(hidden), saxMaxHiddenBlocks), true)
		}
		for _, item := range hidden {
			if cfgHasControlChars(item) || strings.ContainsAny(item, "\\/#") {
				a.add("config/paper-world-defaults.yml", saxReasonListBad, "hidden-blocks 含非法条目", true)
				break
			}
		}
	}

	replacement := saxListItems(text, "replacement-blocks")
	if len(replacement) == 0 {
		a.add("config/paper-world-defaults.yml", saxReasonReplace, "replacement-blocks 未配置", true)
	}

	radiusText, found := cfgLookup(flat, "anticheat.anti-xray.update-radius")
	if found {
		if radius, parsed := cfgParseInt(cfgStripQuotes(radiusText)); !parsed || radius < 0 || radius > saxMaxRadius {
			a.add("config/paper-world-defaults.yml", saxReasonRadius, "update-radius 超出 0..4", true)
		}
	}

	heightText, found := cfgLookup(flat, "anticheat.anti-xray.max-block-height")
	if found {
		if height, parsed := cfgParseInt(cfgStripQuotes(heightText)); !parsed || height < saxMinBlockHeight || height > saxMaxBlockHeight {
			a.add("config/paper-world-defaults.yml", saxReasonHeight, "max-block-height 超出 16..384", true)
		}
	}

	if lava, found := saxBool(flat, "anticheat.anti-xray.lava-obscuring"); found && !lava {
		a.add("config/paper-world-defaults.yml", saxReasonLava, "lava-obscuring 已关闭", false)
	}
	return a
}
