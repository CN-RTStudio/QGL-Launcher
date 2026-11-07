package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	sauMaxFindings = 16
	sauMaxFile     = 256 * 1024
	sauMiss        = "properties-missing"
	sauRead        = "properties-unreadable"
	sauLink        = "properties-symlink"
	sauEmpty       = "properties-empty"
	sauOnlineOff   = "online-mode-disabled"
	sauProxyOff    = "proxy-connections-allowed"
	sauMaxPlayers  = "max-players-invalid"
	sauCompress    = "compression-threshold-invalid"
	sauBindAll     = "server-ip-unset"
	sauIdleTimeout = "idle-timeout-invalid"
)

type AuthConfigFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type AuthConfigAudit struct {
	ServerDir string
	Findings  []AuthConfigFinding
}

func (a *AuthConfigAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= sauMaxFindings {
		return
	}
	a.Findings = append(a.Findings, AuthConfigFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *AuthConfigAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *AuthConfigAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *AuthConfigAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "正版验证与连接策略处于安全区间"
	}
	sorted := make([]AuthConfigFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Detail < sorted[j].Detail
	})
	var b strings.Builder
	for i, f := range sorted {
		if i >= 10 {
			b.WriteString(fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(f.Reason)
		if f.Detail != "" {
			b.WriteString("(")
			b.WriteString(f.Detail)
			b.WriteString(")")
		}
	}
	return b.String()
}

func sauReadProps(serverDir string, a *AuthConfigAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(sauMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(sauRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(sauLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, sauMaxFile)
	if err != nil {
		a.add(sauRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(sauEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func sauBool(props map[string]string, key string) (bool, bool) {
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

func sauInt(props map[string]string, key string) (int, bool, bool) {
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

func AuditServerAuthConfig(serverDir string) *AuthConfigAudit {
	a := &AuthConfigAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(sauMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := sauReadProps(serverDir, a)
	if !ok {
		return a
	}
	if value, has := sauBool(props, "online-mode"); has {
		if !value {
			a.add(sauOnlineOff, "online-mode=false 关闭正版验证", true)
		}
	}
	if value, has := sauBool(props, "prevent-proxy-connections"); has && !value {
		a.add(sauProxyOff, "prevent-proxy-connections=false 允许代理转发", false)
	}
	if value, has, parsed := sauInt(props, "max-players"); has {
		if !parsed {
			a.add(sauMaxPlayers, "max-players 不是整数", true)
		} else if value < 1 {
			a.add(sauMaxPlayers, fmt.Sprintf("max-players=%d 小于 1", value), true)
		} else if value > 100 {
			a.add(sauMaxPlayers, fmt.Sprintf("max-players=%d 超过建议上限 100", value), false)
		}
	}
	if value, has, parsed := sauInt(props, "network-compression-threshold"); has {
		if !parsed {
			a.add(sauCompress, "network-compression-threshold 不是整数", true)
		} else if value < -1 || value > 65536 {
			a.add(sauCompress, fmt.Sprintf("network-compression-threshold=%d 超出 -1..65536", value), false)
		}
	}
	if raw, has := props["server-ip"]; has {
		if cfgStripQuotes(strings.TrimSpace(raw)) == "" {
			a.add(sauBindAll, "server-ip 为空，监听全部网卡", false)
		}
	}
	if value, has, parsed := sauInt(props, "player-idle-timeout"); has {
		if !parsed {
			a.add(sauIdleTimeout, "player-idle-timeout 不是整数", true)
		} else if value < 0 || value > 240 {
			a.add(sauIdleTimeout, fmt.Sprintf("player-idle-timeout=%d 超出 0..240", value), false)
		}
	}
	return a
}
