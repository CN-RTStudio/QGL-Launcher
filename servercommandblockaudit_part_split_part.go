package main

import (
	"os"
	"path/filepath"
	"strings"
)

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
