package main

import (
	"sort"
	"strings"
)

func sprCheckLevelName(a *PropertiesBudgetAudit, props sprProperties) {
	value, ok := props.Values["level-name"]
	if !ok {
		return
	}
	if value == "" {
		a.add("server.properties", sprReasonBadValue, "level-name 为空", false)
		return
	}
	if cfgHasControlChars(value) {
		a.add("server.properties", sprReasonBadValue, "level-name 含控制字符", true)
		return
	}
	if strings.Contains(value, "..") || strings.Contains(value, "/") || strings.Contains(value, "\\") || strings.HasPrefix(value, ".") {
		a.add("server.properties", sprReasonLevelName, "level-name 含路径穿越写法: "+value, true)
		return
	}
	if len(value) > 128 {
		a.add("server.properties", sprReasonBadValue, "level-name 过长", false)
	}
	if strings.ContainsAny(value, ":*?\"<>|") {
		a.add("server.properties", sprReasonBadValue, "level-name 含非法字符: "+value, false)
	}
}

func sprCheckResourcePack(a *PropertiesBudgetAudit, props sprProperties) {
	value, ok := props.Values["resource-pack"]
	if !ok || strings.TrimSpace(value) == "" {
		return
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") {
		a.add("server.properties", sprReasonPackURL, "resource-pack 使用明文 HTTP", false)
	} else if !strings.HasPrefix(lower, "https://") {
		a.add("server.properties", sprReasonPackURL, "resource-pack 不是 HTTPS 地址", false)
	}
	if cfgHasControlChars(value) || strings.Contains(value, "\n") {
		a.add("server.properties", sprReasonBadValue, "resource-pack 含换行或控制字符", true)
	}
	if value, ok := props.Values["resource-pack-sha1"]; ok && strings.TrimSpace(value) == "" {
		a.add("server.properties", sprReasonPackURL, "resource-pack-sha1 为空，客户端无法校验资源包", false)
	}
}

func sprCheckDuplicates(a *PropertiesBudgetAudit, props sprProperties) {
	if len(props.Duplicates) == 0 {
		return
	}
	seen := map[string]bool{}
	items := make([]string, 0, len(props.Duplicates))
	for _, key := range props.Duplicates {
		if seen[key] {
			continue
		}
		seen[key] = true
		items = append(items, key)
	}
	sort.Strings(items)
	if len(items) > 8 {
		items = items[:8]
	}
	a.add("server.properties", sprReasonDupKey, "重复键: "+strings.Join(items, ","), false)
}
