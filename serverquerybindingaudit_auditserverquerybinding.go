package main

import (
	"fmt"
	"os"
	"strings"
)

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

func (a *QueryBindingAudit) Describe() string {
	return describeFindings(a.Findings, func(f QueryBindingFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func sqbLoadText(a *QueryBindingAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func sqbBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}
