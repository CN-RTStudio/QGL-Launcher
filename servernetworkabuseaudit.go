package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	snaMaxFindings = 16
	snaMaxFile     = 256 * 1024
	snaMiss        = "properties-missing"
	snaRead        = "properties-unreadable"
	snaLink        = "properties-symlink"
	snaEmpty       = "properties-empty"
	snaOnlineOff   = "online-mode-disabled"
	snaProxyBypass = "prevent-proxy-connections-off"
	snaRateLimit   = "rate-limit-unbounded"
	snaCompress    = "network-compression-off"
	snaMaxPlayers  = "max-players-excessive"
	snaIdleKick    = "player-idle-timeout-off"
	snaAllowFlight = "allow-flight-enabled"
)

type NetworkAbuseFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type NetworkAbuseAudit struct {
	ServerDir string
	Findings  []NetworkAbuseFinding
}

func (a *NetworkAbuseAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= snaMaxFindings {
		return
	}
	a.Findings = append(a.Findings, NetworkAbuseFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *NetworkAbuseAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *NetworkAbuseAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *NetworkAbuseAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "网络接入与玩家配额未发现滥用风险"
	}
	sorted := make([]NetworkAbuseFinding, len(a.Findings))
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

func snaReadProps(serverDir string, a *NetworkAbuseAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(snaMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(snaRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(snaLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, snaMaxFile)
	if err != nil {
		a.add(snaRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(snaEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func snaInt(props map[string]string, key string) (int, bool, bool) {
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

func snaBool(props map[string]string, key string) (bool, bool) {
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

func AuditServerNetworkAbuse(serverDir string) *NetworkAbuseAudit {
	a := &NetworkAbuseAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(snaMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := snaReadProps(serverDir, a)
	if !ok {
		return a
	}
	if value, has := snaBool(props, "online-mode"); has && !value {
		a.add(snaOnlineOff, "online-mode=false 允许离线客户端冒充任意账号", true)
	}
	if value, has := snaBool(props, "prevent-proxy-connections"); has && !value {
		a.add(snaProxyBypass, "允许代理与 VPN 直连，绕过 IP 封禁", false)
	}
	if value, has, parsed := snaInt(props, "rate-limit"); has {
		if !parsed {
			a.add(snaRateLimit, "rate-limit 不是整数", true)
		} else if value == 0 {
			a.add(snaRateLimit, "rate-limit=0 关闭数据包限速", false)
		} else if value < 0 {
			a.add(snaRateLimit, fmt.Sprintf("rate-limit=%d 为负值", value), true)
		}
	}
	if value, has, parsed := snaInt(props, "network-compression-threshold"); has {
		if !parsed {
			a.add(snaCompress, "network-compression-threshold 不是整数", true)
		} else if value < 0 {
			a.add(snaCompress, "network-compression-threshold<0 关闭压缩", false)
		}
	}
	if value, has, parsed := snaInt(props, "max-players"); has {
		if !parsed {
			a.add(snaMaxPlayers, "max-players 不是整数", true)
		} else if value > 100 {
			a.add(snaMaxPlayers, fmt.Sprintf("max-players=%d 超出建议上限 100", value), false)
		}
	}
	if value, has, parsed := snaInt(props, "player-idle-timeout"); has {
		if !parsed {
			a.add(snaIdleKick, "player-idle-timeout 不是整数", true)
		} else if value == 0 {
			a.add(snaIdleKick, "player-idle-timeout=0 永不休眠踢出挂机玩家", false)
		} else if value < 0 {
			a.add(snaIdleKick, fmt.Sprintf("player-idle-timeout=%d 为负值", value), true)
		}
	}
	if value, has := snaBool(props, "allow-flight"); has && value {
		a.add(snaAllowFlight, "allow-flight=true 放行飞行作弊", false)
	}
	return a
}
