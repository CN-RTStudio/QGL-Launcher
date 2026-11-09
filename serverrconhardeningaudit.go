package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	syrMaxFile      = 256 * 1024
	syrMaxFindings  = 18
	syrDefaultPort  = 25575
	syrMinPassword  = 12
	syrRCONEnabled  = "rcon-enabled"
	syrRCONEmpty    = "rcon-password-empty"
	syrRCONWeak     = "rcon-password-weak"
	syrRCONDefault  = "rcon-password-default"
	syrRCONPortBad  = "rcon-port-invalid"
	syrRCONPortCol  = "rcon-port-collision"
	syrBroadcast    = "rcon-broadcast-enabled"
	syrQueryEnabled = "query-enabled"
	syrQueryPortCol = "query-port-collision"
	syrMissing      = "properties-missing"
	syrUnreadable   = "properties-unreadable"
	syrWeakChars    = "rcon-password-low-variety"
)

type RconHardeningFinding struct {
	Reason   string
	Detail   string
	Blocking bool
}

type RconHardeningAudit struct {
	ServerDir string
	Findings  []RconHardeningFinding
}

func (a *RconHardeningAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, syrMaxFindings, RconHardeningFinding{Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *RconHardeningAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f RconHardeningFinding) bool { return f.Blocking })
}

func (a *RconHardeningAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *RconHardeningAudit) Describe() string {
	return describeAuditFindings("RCON 配置未发现风险", a.Findings, 10,
		func(f RconHardeningFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f RconHardeningFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func syrPasswordVariety(password string) int {
	classes := 0
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false
	for _, r := range password {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	if hasLower {
		classes++
	}
	if hasUpper {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSymbol {
		classes++
	}
	return classes
}

func syrKnownPlaceholder(password string) bool {
	lower := strings.ToLower(strings.TrimSpace(password))
	placeholders := []string{"password", "changeme", "change-me", "rcon", "rconpass", "secret", "admin", "123456", "letmein", "default"}
	for _, item := range placeholders {
		if lower == item {
			return true
		}
	}
	return strings.HasPrefix(lower, "rcon") && len(lower) <= 10
}

func AuditServerRconHardening(serverDir string) *RconHardeningAudit {
	a := &RconHardeningAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(syrMissing, "未配置服务器目录", true)
		return a
	}
	path := filepath.Join(serverDir, "server.properties")
	data, err := readBoundedFile(path, syrMaxFile)
	if err != nil {
		a.add(syrMissing, "缺少或无法读取 server.properties", false)
		return a
	}
	props := pxParseProperties(string(data))
	if props == nil {
		a.add(syrUnreadable, "server.properties 无可解析键值", false)
		return a
	}
	enabled := false
	if on, ok := snmBool(props, "enable-rcon"); ok && on {
		enabled = true
		a.add(syrRCONEnabled, "RCON 已开启", false)
	}
	password := cfgStripQuotes(props["rcon.password"])
	if enabled {
		if password == "" {
			a.add(syrRCONEmpty, "RCON 密码为空", true)
		} else if syrKnownPlaceholder(password) {
			a.add(syrRCONDefault, "RCON 密码是常见占位值", true)
		} else if len(password) < syrMinPassword {
			a.add(syrRCONWeak, fmt.Sprintf("RCON 密码长度 %d 低于 %d", len(password), syrMinPassword), true)
		} else if syrPasswordVariety(password) < 2 {
			a.add(syrWeakChars, "RCON 密码字符种类过少", false)
		}
	}
	rconPort := syrDefaultPort
	if raw, ok := props["rcon.port"]; ok {
		value, parsed := cfgParseInt(raw)
		if !parsed || value < 1 || value > 65535 {
			a.add(syrRCONPortBad, "rcon.port 不是合法端口", true)
		} else {
			rconPort = value
		}
	}
	serverPort := 25565
	if raw, ok := props["server-port"]; ok {
		if value, parsed := cfgParseInt(raw); parsed && value >= 1 && value <= 65535 {
			serverPort = value
		}
	}
	if rconPort == serverPort {
		a.add(syrRCONPortCol, fmt.Sprintf("RCON 端口与游戏端口同为 %d", rconPort), true)
	}
	if on, ok := snmBool(props, "broadcast-rcon-to-ops"); ok && on {
		a.add(syrBroadcast, "RCON 指令会广播给所有运维", false)
	}
	if on, ok := snmBool(props, "enable-query"); ok && on {
		a.add(syrQueryEnabled, "Query 协议已开启，会额外暴露服务器信息", false)
		queryPort := 25565
		if raw, ok := props["query.port"]; ok {
			if value, parsed := cfgParseInt(raw); parsed && value >= 1 && value <= 65535 {
				queryPort = value
			}
		}
		if queryPort == serverPort {
			a.add(syrQueryPortCol, fmt.Sprintf("Query 端口与游戏端口同为 %d", queryPort), false)
		}
	}
	return a
}
