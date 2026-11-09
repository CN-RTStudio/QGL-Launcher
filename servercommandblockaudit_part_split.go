package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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

func AuditServerCommandBlocks(serverDir string) *CommandBlockAudit {
	a := &CommandBlockAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", scbReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", scbReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", scbReasonMissing, "服务器目录不存在", false)
		return a
	}

	if text, ok := scbLoadText(a, serverDir, "server.properties", scbMaxProps); ok {
		props := pxParseProperties(text)
		if len(props) == 0 && strings.TrimSpace(text) != "" {
			a.add("server.properties", scbReasonBadValue, "server.properties 未解析出任何键值", false)
		}
		scbCheckProperties(a, props)
	}

	if text, ok := scbLoadText(a, serverDir, "spigot.yml", scbMaxYAML); ok {
		scbCheckSpigot(a, cfgFlattenYAML(text), text)
		scbCheckWorldSettings(a, cfgFlattenYAML(text))
	}

	if text, ok := scbLoadText(a, serverDir, filepath.Join("config", "paper-world-defaults.yml"), scbMaxYAML); ok {
		flat := cfgFlattenYAML(text)
		if value, ok := cfgLookup(flat, "environment.command-block-output"); ok {
			if !strings.EqualFold(strings.TrimSpace(value), "false") {
				a.add("config/paper-world-defaults.yml", scbReasonSilent, "environment.command-block-output 未关闭，命令输出广播给全部玩家", false)
			}
		}
	}

	return a
}
