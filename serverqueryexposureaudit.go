package main

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	syqMaxFindings  = 16
	syqMaxFile      = 256 * 1024
	syqMissing      = "properties-missing"
	syqLevelEscape  = "level-name-path-escape"
	syqLevelAbsent  = "level-name-empty"
	syqMotdControl  = "motd-control-characters"
	syqMotdLength   = "motd-too-long"
	syqMotdLink     = "motd-contains-url"
	syqIPWildcard   = "server-ip-wildcard"
	syqIPInvalid    = "server-ip-invalid"
	syqIPPublic     = "server-ip-public"
	syqPortInvalid  = "server-port-invalid"
	syqPortLow      = "server-port-privileged"
	syqMaxPlayers   = "max-players-nonpositive"
	syqViewDistance = "view-distance-too-large"
	syqNetCompress  = "network-compression-threshold-negative"
	syqAllowFlight  = "allow-flight-enabled"
)

type QueryExposureFinding struct {
	Reason   string
	Detail   string
	Blocking bool
}

type QueryExposureAudit struct {
	ServerDir string
	Findings  []QueryExposureFinding
}

func (a *QueryExposureAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= syqMaxFindings {
		return
	}
	a.Findings = append(a.Findings, QueryExposureFinding{Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *QueryExposureAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *QueryExposureAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *QueryExposureAudit) Describe() string {
	return describeAuditFindings("对外暴露相关配置未发现风险", a.Findings, 9,
		func(f QueryExposureFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f QueryExposureFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func syqHasControl(text string) bool {
	for _, r := range text {
		if r < 0x20 && r != '\t' {
			return true
		}
		if r == 0x7f {
			return true
		}
		if r >= 0x80 && r <= 0x9f {
			return true
		}
	}
	return false
}

func syqIsPublicIP(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

func AuditServerQueryExposure(serverDir string) *QueryExposureAudit {
	a := &QueryExposureAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(syqMissing, "未配置服务器目录", true)
		return a
	}
	data, err := readBoundedFile(filepath.Join(serverDir, "server.properties"), syqMaxFile)
	if err != nil {
		a.add(syqMissing, "缺少或无法读取 server.properties", false)
		return a
	}
	props := pxParseProperties(string(data))
	if props == nil {
		a.add(syqMissing, "server.properties 无可解析键值", false)
		return a
	}
	levelName := cfgStripQuotes(props["level-name"])
	switch {
	case levelName == "":
		a.add(syqLevelAbsent, "level-name 为空", false)
	case levelName == "." || levelName == "..":
		a.add(syqLevelEscape, "level-name 指向上级或当前目录", true)
	case strings.ContainsAny(levelName, "/\\"):
		a.add(syqLevelEscape, "level-name 含路径分隔符", true)
	case strings.Contains(levelName, ":"):
		a.add(syqLevelEscape, "level-name 含盘符或数据流分隔符", true)
	}
	motd := props["motd"]
	if syqHasControl(motd) {
		a.add(syqMotdControl, "motd 含控制字符", false)
	}
	if utf8.RuneCountInString(motd) > 256 {
		a.add(syqMotdLength, "motd 长度超过 256 字符", false)
	}
	if strings.Contains(strings.ToLower(motd), "http://") || strings.Contains(strings.ToLower(motd), "https://") {
		a.add(syqMotdLink, "motd 内嵌外链，可能被用于钓鱼", false)
	}
	if raw, ok := props["server-ip"]; ok {
		value := cfgStripQuotes(raw)
		if value == "" || value == "0.0.0.0" || value == "::" || value == "*" {
			a.add(syqIPWildcard, "server-ip 绑定到通配地址", false)
		} else if net.ParseIP(value) == nil {
			a.add(syqIPInvalid, "server-ip 不是合法 IP", false)
		} else if syqIsPublicIP(value) {
			a.add(syqIPPublic, "server-ip 绑定公网地址", false)
		}
	}
	if raw, ok := props["server-port"]; ok {
		value, parsed := cfgParseInt(raw)
		if !parsed || value < 1 || value > 65535 {
			a.add(syqPortInvalid, "server-port 不是合法端口", true)
		} else if value < 1024 {
			a.add(syqPortLow, fmt.Sprintf("server-port=%d 属于特权端口段", value), false)
		}
	}
	if raw, ok := props["max-players"]; ok {
		if value, parsed := cfgParseInt(raw); !parsed || value <= 0 {
			a.add(syqMaxPlayers, "max-players 不是正整数", false)
		}
	}
	if raw, ok := props["view-distance"]; ok {
		if value, parsed := cfgParseInt(raw); parsed && value > 16 {
			a.add(syqViewDistance, fmt.Sprintf("view-distance=%d 超过 16", value), false)
		}
	}
	if raw, ok := props["network-compression-threshold"]; ok {
		if value, parsed := cfgParseInt(raw); parsed && value < 0 {
			a.add(syqNetCompress, "network-compression-threshold 为负值", false)
		}
	}
	if on, ok := snmBool(props, "allow-flight"); ok && on {
		a.add(syqAllowFlight, "allow-flight 开启会放开飞行类作弊", false)
	}
	return a
}
