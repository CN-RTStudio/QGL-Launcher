package main

import (
	"os"
	"strings"
)

func AuditServerConnectionFlood(serverDir string) *ConnectionFloodAudit {
	a := &ConnectionFloodAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", cfdReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", cfdReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", cfdReasonMissing, "服务器目录不存在", false)
		return a
	}

	props := map[string]string{}
	if text, ok := cfdLoad(a, serverDir, "server.properties", cfdMaxProps); ok {
		props = pxParseProperties(text)
		if len(props) == 0 && strings.TrimSpace(text) != "" {
			a.add("server.properties", cfdReasonBadConfig, "server.properties 未解析出任何键值", false)
		}
		cfdCheckProperties(a, props)
	}

	bukkitFlat := map[string]string{}
	if text, ok := cfdLoad(a, serverDir, "bukkit.yml", cfdMaxYAML); ok {
		bukkitFlat = cfgFlattenYAML(text)
		cfdCheckThrottle(a, "bukkit.yml", bukkitFlat)
	}

	spigotFlat := map[string]string{}
	if text, ok := cfdLoad(a, serverDir, "spigot.yml", cfdMaxYAML); ok {
		spigotFlat = cfgFlattenYAML(text)
		cfdCheckSpigot(a, spigotFlat)
	}

	paperFlat := map[string]string{}
	if text, ok := cfdLoad(a, serverDir, "config/paper-global.yml", cfdMaxYAML); ok {
		paperFlat = cfgFlattenYAML(text)
		cfdCheckPaper(a, paperFlat)
	}

	if len(spigotFlat) > 0 && len(bukkitFlat) > 0 {
		cfdCheckThrottleConflict(a, props, spigotFlat, bukkitFlat)
	}

	if len(props) == 0 && len(bukkitFlat) == 0 && len(spigotFlat) == 0 && len(paperFlat) == 0 {
		a.add(".", cfdReasonMissing, "未发现连接节流相关配置", false)
	}
	return a
}
