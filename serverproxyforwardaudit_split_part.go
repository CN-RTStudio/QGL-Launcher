package main

import (
	"os"
	"strings"
)

func AuditServerProxyForwarding(serverDir string) *ProxyForwardAudit {
	a := &ProxyForwardAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", pfwReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", pfwReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", pfwReasonMissing, "服务器目录不存在", false)
		return a
	}

	props := map[string]string{}
	if text, ok := pfwLoadText(a, serverDir, "server.properties", pfwMaxProps); ok {
		props = pxParseProperties(text)
		if len(props) == 0 && strings.TrimSpace(text) != "" {
			a.add("server.properties", pfwReasonBadConfig, "server.properties 未解析出任何键值", false)
		}
		pfwCheckProperties(a, props)
	}

	spigotFlat := map[string]string{}
	if text, ok := pfwLoadText(a, serverDir, "spigot.yml", pfwMaxYAML); ok {
		spigotFlat = cfgFlattenYAML(text)
		if len(spigotFlat) == 0 && strings.TrimSpace(text) != "" {
			a.add("spigot.yml", pfwReasonBadConfig, "spigot.yml 未解析出任何键值", false)
		}
	}

	paperFlat := map[string]string{}
	if text, ok := pfwLoadText(a, serverDir, "config/paper-global.yml", pfwMaxYAML); ok {
		paperFlat = cfgFlattenYAML(text)
		if len(paperFlat) == 0 && strings.TrimSpace(text) != "" {
			a.add("config/paper-global.yml", pfwReasonBadConfig, "paper-global.yml 未解析出任何键值", false)
		}
	}

	pfwCheckSpigot(a, spigotFlat)
	pfwCheckPaperProxy(a, paperFlat)
	if len(props) > 0 {
		pfwCheckCrossSource(a, props, paperFlat)
	}

	if len(props) == 0 && len(spigotFlat) == 0 && len(paperFlat) == 0 {
		a.add(".", pfwReasonMissing, "未发现代理或在线模式配置", false)
	}
	return a
}
