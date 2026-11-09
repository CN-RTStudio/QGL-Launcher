package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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

func AuditServerPropertiesBudget(serverDir string) *PropertiesBudgetAudit {
	a := &PropertiesBudgetAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", sprReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sprReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", sprReasonMissing, "服务器目录不存在", false)
		return a
	}
	path := filepath.Join(serverDir, "server.properties")
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add("server.properties", sprReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, sprMaxProps)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			a.add(".", sprReasonMissing, "未发现 server.properties", false)
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add("server.properties", sprReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", sprMaxProps), true)
			return a
		}
		a.add("server.properties", sprReasonUnreadable, "配置文件不可读", false)
		return a
	}
	props := sprParseProperties(string(data))
	a.Keys = len(props.Values)
	if a.Keys == 0 && strings.TrimSpace(string(data)) != "" {
		a.add("server.properties", sprReasonBadConfig, "未解析出任何键值", false)
		return a
	}
	if props.LongLines > 0 {
		a.add("server.properties", sprReasonBadConfig, fmt.Sprintf("存在 %d 行超长键值", props.LongLines), false)
	}
	sprCheckViewDistance(a, props)
	sprCheckCompression(a, props)
	sprCheckWatchdog(a, props)
	sprCheckPorts(a, props)
	sprCheckLevelName(a, props)
	sprCheckResourcePack(a, props)
	sprCheckDuplicates(a, props)
	if a.Keys == 0 {
		a.add(".", sprReasonMissing, "server.properties 为空", false)
	}
	return a
}
