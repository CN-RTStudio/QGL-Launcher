package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	sprMaxFindings       = 48
	sprMaxProps          = 256 * 1024
	sprMaxViewDistance   = 16
	sprMinViewDistance   = 3
	sprMaxCompression    = 1024
	sprReasonOK          = "ok"
	sprReasonMissing     = "missing"
	sprReasonSymlink     = "symlink"
	sprReasonTooLarge    = "too-large"
	sprReasonUnreadable  = "unreadable"
	sprReasonBadConfig   = "bad-config"
	sprReasonBadValue    = "bad-value"
	sprReasonDupKey      = "duplicate-key"
	sprReasonViewLarge   = "view-distance-large"
	sprReasonViewSmall   = "view-distance-small"
	sprReasonSimDistance = "simulation-exceeds-view"
	sprReasonCompression = "compression-threshold"
	sprReasonWatchdog    = "watchdog-disabled"
	sprReasonPortClash   = "port-conflict"
	sprReasonLevelName   = "level-name-traversal"
	sprReasonPackURL     = "insecure-resource-pack"
)

type PropertiesBudgetFinding = auditFinding
type PropertiesBudgetAudit struct {
	ServerDir string
	Keys      int
	Findings  []PropertiesBudgetFinding
}

func (a *PropertiesBudgetAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sprMaxFindings, PropertiesBudgetFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *PropertiesBudgetAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropertiesBudgetFinding) bool { return f.Blocking })
}
func (a *PropertiesBudgetAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PropertiesBudgetFinding) bool { return f.Reason != sprReasonOK && !f.Blocking })
}

func (a *PropertiesBudgetAudit) Describe() string {
	return describeFindings(a.Findings, func(f PropertiesBudgetFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

type sprProperties struct {
	Values     map[string]string
	Duplicates []string
	LongLines  int
}

func sprParseProperties(text string) sprProperties {
	out := sprProperties{Values: map[string]string{}}
	seen := map[string]bool{}
	text = strings.TrimPrefix(text, "\ufeff")
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		if len(line) > 4096 {
			out.LongLines++
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		if key == "" {
			continue
		}
		value := strings.TrimSpace(line[idx+1:])
		if seen[key] {
			out.Duplicates = append(out.Duplicates, key)
			continue
		}
		seen[key] = true
		out.Values[key] = value
	}
	return out
}

func sprCheckCompression(a *PropertiesBudgetAudit, props sprProperties) {
	value, ok := props.Values["network-compression-threshold"]
	if !ok {
		return
	}
	n, valid := cfgParseInt(value)
	if !valid {
		a.add("server.properties", sprReasonBadValue, "network-compression-threshold 不是合法整数: "+value, false)
		return
	}
	if n < -1 || n > sprMaxCompression {
		a.add("server.properties", sprReasonCompression, fmt.Sprintf("network-compression-threshold=%d 超出 -1..%d", n, sprMaxCompression), false)
	}
}
func sprCheckWatchdog(a *PropertiesBudgetAudit, props sprProperties) {
	value, ok := props.Values["max-tick-time"]
	if !ok {
		return
	}
	n, valid := cfgParseInt(value)
	if !valid {
		a.add("server.properties", sprReasonBadValue, "max-tick-time 不是合法整数: "+value, false)
		return
	}
	if n < 0 {
		a.add("server.properties", sprReasonWatchdog, fmt.Sprintf("max-tick-time=%d 关闭了卡顿看门狗", n), true)
	} else if n == 0 {
		a.add("server.properties", sprReasonWatchdog, "max-tick-time=0 关闭了卡顿看门狗", true)
	} else if n < 30000 {
		a.add("server.properties", sprReasonBadValue, fmt.Sprintf("max-tick-time=%d 毫秒过于敏感", n), false)
	}
}

func sprCheckPorts(a *PropertiesBudgetAudit, props sprProperties) {
	ports := map[string]int{}
	for _, key := range []string{"server-port", "query.port", "rcon.port"} {
		n, ok := sprCheckInt(a, props, key)
		if !ok {
			continue
		}
		if n < 1 || n > 65535 {
			a.add("server.properties", sprReasonBadValue, fmt.Sprintf("%s=%d 超出端口范围", key, n), false)
			continue
		}
		ports[key] = n
	}
	if serverPort, ok := ports["server-port"]; ok {
		for _, key := range []string{"query.port", "rcon.port"} {
			if n, exists := ports[key]; exists && n == serverPort {
				a.add("server.properties", sprReasonPortClash, fmt.Sprintf("%s 与 server-port 同为 %d", key, n), false)
			}
		}
	}
}

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

func sprCheckInt(a *PropertiesBudgetAudit, props sprProperties, key string) (int, bool) {
	value, ok := props.Values[key]
	if !ok {
		return 0, false
	}
	n, valid := cfgParseInt(value)
	if !valid {
		a.add("server.properties", sprReasonBadValue, key+" 不是合法整数: "+value, false)
		return 0, false
	}
	return n, true
}

func sprCheckViewDistance(a *PropertiesBudgetAudit, props sprProperties) {
	view, hasView := sprCheckInt(a, props, "view-distance")
	simulation, hasSimulation := sprCheckInt(a, props, "simulation-distance")
	if hasView {
		if view > sprMaxViewDistance {
			a.add("server.properties", sprReasonViewLarge, fmt.Sprintf("view-distance=%d 超过 %d，区块与实体负载放大", view, sprMaxViewDistance), false)
		}
		if view < sprMinViewDistance {
			a.add("server.properties", sprReasonViewSmall, fmt.Sprintf("view-distance=%d 低于 %d", view, sprMinViewDistance), false)
		}
	}
	if hasSimulation && hasView && simulation > view {
		a.add("server.properties", sprReasonSimDistance, fmt.Sprintf("simulation-distance=%d 大于 view-distance=%d", simulation, view), false)
	}
}
