package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	scbMaxFindings      = 48
	scbMaxProps         = 256 * 1024
	scbMaxYAML          = 512 * 1024
	scbDefaultChainMax  = 65536
	scbHardChainMax     = 262144
	scbDefaultForkMax   = 256
	scbHardForkMax      = 1024
	scbReasonOK         = "ok"
	scbReasonMissing    = "missing"
	scbReasonSymlink    = "symlink"
	scbReasonTooLarge   = "too-large"
	scbReasonUnreadable = "unreadable"
	scbReasonBadValue   = "bad-value"
	scbReasonChainLong  = "command-chain-too-long"
	scbReasonForkHigh   = "command-fork-too-high"
	scbReasonOpHigh     = "op-level-maximum"
	scbReasonFnHigh     = "function-level-maximum"
	scbReasonRCECombo   = "command-block-rce-surface"
	scbReasonSilent     = "silent-commandblock-console"
	scbReasonNoBlock    = "command-block-disabled"
	scbReasonSpamList   = "spam-exclusion-widened"
)

type CommandBlockFinding = auditFinding

type CommandBlockAudit struct {
	ServerDir string
	Findings  []CommandBlockFinding
}

func scbCheckProperties(a *CommandBlockAudit, props map[string]string) {
	enabled, known := scbPropBool(props, "enable-command-block")
	if !known {
		a.add("server.properties", scbReasonNoBlock, "缺少 enable-command-block 声明，按默认禁用处理", false)
	} else if !enabled {
		a.add("server.properties", scbReasonNoBlock, "enable-command-block=false，命令方块全部禁用", false)
	}

	chain, chainKnown := scbPropInt(props, "maxCommandChainLength")
	if chainKnown {
		switch {
		case chain <= 0:
			a.add("server.properties", scbReasonChainLong, "maxCommandChainLength 非正数，命令链无上限", true)
		case chain > scbHardChainMax:
			a.add("server.properties", scbReasonChainLong, fmt.Sprintf("maxCommandChainLength=%d 超过硬上限 %d", chain, scbHardChainMax), true)
		case chain > scbDefaultChainMax:
			a.add("server.properties", scbReasonChainLong, fmt.Sprintf("maxCommandChainLength=%d 高于默认 %d", chain, scbDefaultChainMax), false)
		}
	}

	fork, forkKnown := scbPropInt(props, "maxCommandForkCount")
	if forkKnown {
		switch {
		case fork <= 0:
			a.add("server.properties", scbReasonForkHigh, "maxCommandForkCount 非正数，命令分叉不受限", true)
		case fork > scbHardForkMax:
			a.add("server.properties", scbReasonForkHigh, fmt.Sprintf("maxCommandForkCount=%d 超过硬上限 %d", fork, scbHardForkMax), true)
		case fork > scbDefaultForkMax:
			a.add("server.properties", scbReasonForkHigh, fmt.Sprintf("maxCommandForkCount=%d 高于默认 %d", fork, scbDefaultForkMax), false)
		}
	}

	opLevel, opKnown := scbPropInt(props, "op-permission-level")
	if opKnown {
		switch {
		case opLevel < 1 || opLevel > 4:
			a.add("server.properties", scbReasonBadValue, fmt.Sprintf("op-permission-level=%d 超出 1..4", opLevel), false)
		case opLevel >= 4:
			a.add("server.properties", scbReasonOpHigh, "op-permission-level=4，管理员可执行全部命令", false)
		}
	}

	fnLevel, fnKnown := scbPropInt(props, "function-permission-level")
	if fnKnown {
		switch {
		case fnLevel < 1 || fnLevel > 4:
			a.add("server.properties", scbReasonBadValue, fmt.Sprintf("function-permission-level=%d 超出 1..4", fnLevel), false)
		case fnLevel >= 4:
			a.add("server.properties", scbReasonFnHigh, "function-permission-level=4，函数以最高权限执行", false)
		}
	}

	if known && enabled && fnKnown && fnLevel >= 4 {
		a.add("server.properties", scbReasonRCECombo, "命令方块启用且函数权限为 4，数据包函数可直接执行高权限命令", true)
	}
	if known && enabled && opKnown && opLevel >= 4 {
		a.add("server.properties", scbReasonRCECombo, "命令方块启用且 op 权限为 4，命令方块可执行高权限命令", true)
	}
}

func scbCheckSpigot(a *CommandBlockAudit, flat map[string]string, text string) {
	silent, ok := cfgLookup(flat, "commands.silent-commandblock-console")
	if ok && strings.EqualFold(strings.TrimSpace(silent), "true") {
		a.add("spigot.yml", scbReasonSilent, "commands.silent-commandblock-console=true，命令方块输出不再进入控制台", false)
	}

	items := scbScanSpamExclusions(text)
	if len(items) > 0 {
		if len(items) > 8 {
			a.add("spigot.yml", scbReasonSpamList, fmt.Sprintf("commands.spam-exclusions 条目 %d 个，命令刷屏限制被大幅放宽", len(items)), false)
		}
		for _, item := range items {
			lower := strings.ToLower(item)
			if strings.Contains(lower, "/*") || strings.HasPrefix(lower, "/") {
				a.add("spigot.yml", scbReasonSpamList, "commands.spam-exclusions 放宽到整类命令: "+item, false)
			}
		}
	}

	tabComplete, ok := cfgLookup(flat, "commands.tab-complete")
	if ok {
		lower := strings.ToLower(strings.TrimSpace(tabComplete))
		if lower != "0" && lower != "-1" && lower != "1" {
			if _, perr := cfgParseInt(tabComplete); !perr {
				a.add("spigot.yml", scbReasonBadValue, "commands.tab-complete 取值非法: "+tabComplete, false)
			}
		}
	}
}

func scbScanSpamExclusions(text string) []string {
	lines := strings.Split(text, "\n")
	items := make([]string, 0, 16)
	inSection := false
	baseIndent := 0
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		if !inSection {
			if strings.HasPrefix(trimmed, "spam-exclusions:") {
				inSection = true
				baseIndent = indent
			}
			continue
		}
		if indent <= baseIndent && !strings.HasPrefix(trimmed, "-") {
			break
		}
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			value = cfgStripQuotes(value)
			if value != "" {
				items = append(items, value)
			}
		}
	}
	return items
}
func scbCheckWorldSettings(a *CommandBlockAudit, flat map[string]string) {
	keys := make([]string, 0, len(flat))
	for key := range flat {
		if strings.HasSuffix(key, "command-block-output") || strings.HasSuffix(key, "command-blocks-enabled") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return
	}
	for _, key := range keys {
		value := strings.ToLower(strings.TrimSpace(flat[key]))
		if key == "world-settings.default.command-blocks-enabled" && value != "true" {
			a.add("spigot.yml", scbReasonNoBlock, "world-settings.default.command-blocks-enabled=false，世界级命令方块禁用", false)
		}
	}
}
