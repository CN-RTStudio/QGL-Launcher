package main

import (
	"fmt"
	"os"
	"strings"
)

func sqbCheckBukkit(a *QueryBindingAudit, flat map[string]string) {
	if value, ok := cfgLookup(flat, "settings.query-plugins"); ok {
		on, known := spxBool(value)
		if !known {
			a.add("bukkit.yml", sqbReasonBadValue, "settings.query-plugins 取值非法: "+value, false)
		} else if on {
			a.add("bukkit.yml", sqbReasonQueryOn, "settings.query-plugins=true，查询响应包含全部插件版本", false)
		}
	}
	if value, ok := cfgLookup(flat, "settings.connection-throttle"); ok {
		n, valid := cfgParseInt(value)
		if !valid {
			a.add("bukkit.yml", sqbReasonBadValue, "settings.connection-throttle 取值非法: "+value, false)
		} else if n < 0 {
			a.add("bukkit.yml", sqbReasonBadValue, fmt.Sprintf("settings.connection-throttle=%d 为负值，连接节流被关闭", n), false)
		}
	}
}

func AuditServerQueryBinding(serverDir string) *QueryBindingAudit {
	a := &QueryBindingAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", sqbReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sqbReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", sqbReasonMissing, "服务器目录不存在", false)
		return a
	}

	if text, ok := sqbLoadText(a, serverDir, "server.properties", sqbMaxProps); ok {
		props := pxParseProperties(text)
		if len(props) == 0 && strings.TrimSpace(text) != "" {
			a.add("server.properties", sqbReasonBadValue, "server.properties 未解析出任何键值", false)
		}
		sqbCheckQuery(a, props)
	}

	if text, ok := sqbLoadText(a, serverDir, "bukkit.yml", sqbMaxBukkit); ok {
		sqbCheckBukkit(a, cfgFlattenYAML(text))
	}

	return a
}
