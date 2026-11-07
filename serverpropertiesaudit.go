package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	prpMaxFindings   = 16
	prpMaxFile       = 256 * 1024
	prpMinPass       = 8
	prpMaxPlayers    = 200
	prpMiss          = "properties-file-missing"
	prpRead          = "properties-file-unreadable"
	prpLink          = "properties-file-symlink"
	prpEmpty         = "properties-file-empty"
	prpOffline       = "properties-online-mode-off"
	prpRconOpen      = "properties-rcon-no-password"
	prpRconWeak      = "properties-rcon-short-password"
	prpRconBroadcast = "properties-rcon-broadcast"
	prpQueryOpen     = "properties-query-enabled"
	prpPortClash     = "properties-query-port-clash"
	prpWhiteListOff  = "properties-whitelist-off"
	prpEnforceOff    = "properties-enforce-whitelist-off"
	prpSpawnZero     = "properties-spawn-protection-zero"
	prpLevelTraverse = "properties-level-name-traversal"
	prpPlayerLimit   = "properties-max-players-high"
)

var prpLevelPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type PropertiesFinding struct {
	Key      string
	Reason   string
	Detail   string
	Blocking bool
}

type PropertiesAudit struct {
	ServerDir string
	Values    map[string]string
	Findings  []PropertiesFinding
}

func (a *PropertiesAudit) add(key, reason, detail string, blocking bool) {
	if len(a.Findings) >= prpMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PropertiesFinding{Key: key, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PropertiesAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PropertiesAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PropertiesAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "server.properties 安全项全部通过"
	}
	sorted := make([]PropertiesFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Key < sorted[j].Key
	})
	parts := make([]string, 0, len(sorted))
	for i, f := range sorted {
		if i >= 10 {
			parts = append(parts, fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		parts = append(parts, f.Reason+"("+f.Key+")")
	}
	return strings.Join(parts, "；")
}

func prpParse(text string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		if key == "" {
			continue
		}
		values[key] = cfgStripQuotes(strings.TrimSpace(trimmed[eq+1:]))
	}
	return values
}

func prpBool(values map[string]string, key string, fallback bool) bool {
	raw, ok := values[key]
	if !ok {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true":
		return true
	case "false":
		return false
	}
	return fallback
}

func prpInt(values map[string]string, key string, fallback int) int {
	raw, ok := values[key]
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return n
}

func prpAuditValues(values map[string]string, a *PropertiesAudit) {
	if !prpBool(values, "online-mode", true) {
		a.add("online-mode", prpOffline, "关闭正版验证会接受任意离线身份", true)
	}

	if prpBool(values, "enable-rcon", false) {
		password, ok := values["rcon.password"]
		if !ok || strings.TrimSpace(password) == "" {
			a.add("rcon.password", prpRconOpen, "RCON 已启用但未设置密码", true)
		} else if len(password) < prpMinPass {
			a.add("rcon.password", prpRconWeak, fmt.Sprintf("RCON 密码长度 %d 小于 %d", len(password), prpMinPass), false)
		}
		if prpBool(values, "broadcast-rcon-to-ops", false) {
			a.add("broadcast-rcon-to-ops", prpRconBroadcast, "RCON 输出会广播给全部 OP", false)
		}
	}

	if prpBool(values, "enable-query", false) {
		a.add("enable-query", prpQueryOpen, "Query 协议会暴露在线人数与版本信息", false)
		if prpInt(values, "query.port", 25565) == prpInt(values, "server-port", 25565) {
			a.add("query.port", prpPortClash, "Query 端口与游戏端口相同", false)
		}
	}

	if !prpBool(values, "white-list", false) {
		a.add("white-list", prpWhiteListOff, "白名单未启用", false)
	} else if !prpBool(values, "enforce-whitelist", false) {
		a.add("enforce-whitelist", prpEnforceOff, "白名单未强制踢出非名单玩家", false)
	}

	if prpInt(values, "spawn-protection", 16) == 0 {
		a.add("spawn-protection", prpSpawnZero, "出生点保护半径为 0", false)
	}

	if level, ok := values["level-name"]; ok {
		if !prpLevelPattern.MatchString(level) {
			a.add("level-name", prpLevelTraverse, "世界目录名包含路径分隔或特殊字符", true)
		}
	}

	if n := prpInt(values, "max-players", 20); n > prpMaxPlayers {
		a.add("max-players", prpPlayerLimit, fmt.Sprintf("max-players=%d 超过建议上限 %d", n, prpMaxPlayers), false)
	}
}

func AuditServerProperties(serverDir string) *PropertiesAudit {
	a := &PropertiesAudit{ServerDir: serverDir, Values: map[string]string{}}
	if serverDir == "" {
		a.add("server.properties", prpMiss, "未配置服务器目录", false)
		return a
	}
	path := filepath.Join(serverDir, "server.properties")
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		a.add("server.properties", prpMiss, "缺少 server.properties", false)
		return a
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add("server.properties", prpRead, err.Error(), true)
		return a
	}
	if link {
		a.add("server.properties", prpLink, "配置文件是符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, prpMaxFile)
	if err != nil {
		a.add("server.properties", prpRead, err.Error(), true)
		return a
	}
	text := strings.TrimPrefix(strings.TrimSpace(string(data)), "\ufeff")
	if text == "" {
		a.add("server.properties", prpEmpty, "配置文件为空", false)
		return a
	}
	a.Values = prpParse(text)
	prpAuditValues(a.Values, a)
	return a
}
