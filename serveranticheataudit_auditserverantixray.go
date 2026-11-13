package main

import (
	"fmt"
	"os"
	"strings"
)

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
