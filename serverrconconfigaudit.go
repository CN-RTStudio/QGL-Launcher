package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	rcnMaxFindings = 16
	rcnMaxFile     = 256 * 1024
	rcnMiss        = "properties-missing"
	rcnRead        = "properties-unreadable"
	rcnLink        = "properties-symlink"
	rcnEmpty       = "properties-empty"
	rcnPwEmpty     = "rcon-password-empty"
	rcnPwShort     = "rcon-password-short"
	rcnPwWeak      = "rcon-password-weak"
	rcnBroadcast   = "rcon-broadcast-to-ops"
	rcnPortInvalid = "rcon-port-invalid"
	rcnPortClash   = "rcon-port-clash"
	rcnQueryOn     = "query-enabled"
	rcnQueryPort   = "query-port-invalid"
	rcnBindAll     = "server-ip-unset"
)

var rcnWeakPasswords = []string{"rcon", "password", "changeme", "admin", "123456", "letmein", "minecraft"}

type RconConfigFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type RconConfigAudit struct {
	ServerDir string
	Findings  []RconConfigFinding
}

func (a *RconConfigAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= rcnMaxFindings {
		return
	}
	a.Findings = append(a.Findings, RconConfigFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *RconConfigAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *RconConfigAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *RconConfigAudit) Describe() string {
	return describeAuditFindings("RCON 与查询端口配置处于安全区间", a.Findings, 10,
		func(f RconConfigFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f RconConfigFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func rcnReadProps(serverDir string, a *RconConfigAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rcnMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rcnRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(rcnLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, rcnMaxFile)
	if err != nil {
		a.add(rcnRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(rcnEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func rcnBool(props map[string]string, key string) (bool, bool) {
	raw, ok := props[key]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "on", "yes":
		return true, true
	case "false", "off", "no":
		return false, true
	}
	return false, false
}

func rcnInt(props map[string]string, key string) (int, bool, bool) {
	raw, ok := props[key]
	if !ok {
		return 0, false, false
	}
	value, parsed := cfgParseInt(cfgStripQuotes(raw))
	if !parsed {
		return 0, true, false
	}
	return value, true, true
}

func rcnWeak(password string) bool {
	lower := strings.ToLower(password)
	for _, word := range rcnWeakPasswords {
		if lower == word || strings.HasPrefix(lower, word) {
			return true
		}
	}
	return false
}

func rcnAuditPassword(props map[string]string, a *RconConfigAudit) {
	enabled, has := rcnBool(props, "rcon.enabled")
	if !has || !enabled {
		return
	}
	raw, ok := props["rcon.password"]
	if !ok {
		a.add(rcnPwEmpty, "启用 RCON 但未设置密码", true)
		return
	}
	password := cfgStripQuotes(strings.TrimSpace(raw))
	if password == "" {
		a.add(rcnPwEmpty, "rcon.password 为空", true)
		return
	}
	if len(password) < 12 {
		a.add(rcnPwShort, fmt.Sprintf("密码长度 %d 小于 12", len(password)), true)
	}
	if rcnWeak(password) {
		a.add(rcnPwWeak, "密码命中常见弱口令词表", true)
	}
	if value, has := rcnBool(props, "broadcast-rcon-to-ops"); has && value {
		a.add(rcnBroadcast, "RCON 输出会广播给所有 OP", false)
	}
}

func AuditServerRconConfig(serverDir string) *RconConfigAudit {
	a := &RconConfigAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(rcnMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := rcnReadProps(serverDir, a)
	if !ok {
		return a
	}
	rcnAuditPassword(props, a)
	rconPort, hasRconPort, rconParsed := rcnInt(props, "rcon.port")
	if hasRconPort {
		if !rconParsed {
			a.add(rcnPortInvalid, "rcon.port 不是整数", true)
		} else if rconPort < 1024 || rconPort > 65535 {
			a.add(rcnPortInvalid, fmt.Sprintf("rcon.port=%d 超出 1024..65535", rconPort), true)
		}
	}
	if value, has := rcnBool(props, "enable-query"); has && value {
		a.add(rcnQueryOn, "enable-query=true 暴露服务器元数据", false)
	}
	queryPort, hasQueryPort, queryParsed := rcnInt(props, "query.port")
	if hasQueryPort {
		if !queryParsed {
			a.add(rcnQueryPort, "query.port 不是整数", true)
		} else if queryPort < 1024 || queryPort > 65535 {
			a.add(rcnQueryPort, fmt.Sprintf("query.port=%d 超出 1024..65535", queryPort), true)
		}
		if rconParsed && queryParsed && queryPort == rconPort {
			a.add(rcnPortClash, fmt.Sprintf("query.port 与 rcon.port 同为 %d", queryPort), true)
		}
	}
	if raw, has := props["server-ip"]; has {
		if cfgStripQuotes(strings.TrimSpace(raw)) == "" {
			a.add(rcnBindAll, "server-ip 为空，管理端口监听全部网卡", false)
		}
	}
	return a
}
