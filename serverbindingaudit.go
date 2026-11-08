package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	bindingReasonOK           = "ok"
	bindingReasonMissing      = "missing"
	bindingReasonSymlink      = "symlink"
	bindingReasonTooLarge     = "too-large"
	bindingReasonUnreadable   = "unreadable"
	bindingReasonBadBoolean   = "bad-boolean"
	bindingReasonOfflineMode  = "offline-mode"
	bindingReasonBindAll      = "bind-all-interfaces"
	bindingReasonBindPublic   = "bind-public-address"
	bindingReasonBindLoopback = "bind-loopback"
	bindingReasonBadBind      = "bad-bind-address"
	bindingReasonSecureChat   = "secure-profile-unenforced"
	bindingReasonProxyAllowed = "proxy-connections-allowed"
	bindingReasonStatusPublic = "status-exposed"
	bindingReasonBadCompress  = "bad-compression-threshold"
	bindingReasonBadPlayerCap = "bad-player-cap"
	bindingReasonBadViewDist  = "bad-view-distance"
)

type BindingFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerBindingAudit struct {
	Path     string
	Present  bool
	Findings []BindingFinding
}

func (a *ServerBindingAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f BindingFinding) bool { return f.Blocking })
}

func (a *ServerBindingAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != bindingReasonOK {
			return true
		}
	}
	return false
}

func (a *ServerBindingAudit) Codes() []string {
	if a == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(a.Findings))
	codes := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == bindingReasonOK {
			continue
		}
		if _, ok := seen[f.Reason]; ok {
			continue
		}
		seen[f.Reason] = struct{}{}
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a *ServerBindingAudit) Describe() string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == bindingReasonOK {
			continue
		}
		if f.Key != "" {
			parts = append(parts, fmt.Sprintf("%s=%q(%s): %s", f.Key, f.Value, f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s", f.Reason, f.Detail))
	}
	return strings.Join(parts, "；")
}

func AuditServerBinding(serverDir string) (*ServerBindingAudit, error) {
	path := filepath.Join(serverDir, "server.properties")
	audit := &ServerBindingAudit{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.Findings = append(audit.Findings, BindingFinding{
				Reason: bindingReasonMissing, Detail: "server.properties 不存在，无法审计网络暴露策略",
			})
			return audit, nil
		}
		return nil, fmt.Errorf("读取 server.properties 属性失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, BindingFinding{
			Reason: bindingReasonSymlink, Detail: "server.properties 是符号链接，可能指向服务器目录之外",
			Blocking: true,
		})
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, BindingFinding{
			Reason: bindingReasonUnreadable, Detail: "server.properties 不是普通文件", Blocking: true,
		})
		return audit, nil
	}
	if info.Size() > int64(localTextConfigMaxBytes) {
		audit.Findings = append(audit.Findings, BindingFinding{
			Reason:   bindingReasonTooLarge,
			Detail:   fmt.Sprintf("server.properties 大小 %d 字节，超过 %d 上限", info.Size(), localTextConfigMaxBytes),
			Blocking: true,
		})
		return audit, nil
	}
	data, err := readBoundedFile(path, int64(localTextConfigMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("读取 server.properties 失败: %w", err)
	}
	props := parseServerProperties(data)
	audit.Present = true

	audit.auditOnlineMode(props)
	audit.auditBindAddress(props)
	audit.auditSecureProfile(props)
	audit.auditProxyConnections(props)
	audit.auditStatus(props)
	audit.auditNumericLimits(props)
	return audit, nil
}

func (a *ServerBindingAudit) appendFinding(key, value, reason, detail string, blocking bool) {
	a.Findings = append(a.Findings, BindingFinding{
		Key: key, Value: value, Reason: reason, Detail: detail, Blocking: blocking,
	})
}

func (a *ServerBindingAudit) auditOnlineMode(props *serverProperties) {
	raw, ok := props.Get("online-mode")
	if !ok {
		return
	}
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "true":
		return
	case "false":
		a.appendFinding("online-mode", raw, bindingReasonOfflineMode,
			"离线模式关闭了 Mojang 会话校验，任何客户端都能冒用任意玩家名与 UUID", true)
	default:
		a.appendFinding("online-mode", raw, bindingReasonBadBoolean,
			"online-mode 取值不是 true/false，服务端会按默认逻辑处理，行为不可预期", false)
	}
}

func (a *ServerBindingAudit) auditBindAddress(props *serverProperties) {
	raw, ok := props.Get("server-ip")
	if !ok {
		return
	}
	addr := strings.TrimSpace(raw)
	if addr == "" {
		a.appendFinding("server-ip", raw, bindingReasonBindAll,
			"server-ip 为空时服务端监听所有网卡，公网可达的主机会直接暴露游戏端口", false)
		return
	}
	if containsControlByte(addr) || len(addr) > 253 {
		a.appendFinding("server-ip", raw, bindingReasonBadBind,
			"server-ip 含控制字符或长度超限，无法作为合法绑定地址", true)
		return
	}
	if strings.EqualFold(addr, "0.0.0.0") || strings.EqualFold(addr, "*") {
		a.appendFinding("server-ip", raw, bindingReasonBindAll,
			"server-ip 显式绑定通配地址，等同监听所有网卡", false)
		return
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		a.appendFinding("server-ip", raw, bindingReasonBadBind,
			"server-ip 不是可解析的 IP 字面量，服务端可能回退到默认网卡", false)
		return
	}
	if ip.IsLoopback() {
		a.appendFinding("server-ip", raw, bindingReasonBindLoopback,
			"仅绑定回环地址，外部客户端不可达", false)
		return
	}
	a.appendFinding("server-ip", raw, bindingReasonBindPublic,
		"绑定到非回环地址，局域网/公网可直接连接该端口", false)
}

func (a *ServerBindingAudit) auditSecureProfile(props *serverProperties) {
	raw, ok := props.Get("enforce-secure-profile")
	if !ok {
		return
	}
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "true":
		return
	case "false":
		a.appendFinding("enforce-secure-profile", raw, bindingReasonSecureChat,
			"关闭安全聊天档案校验后，未签名消息可被伪造为他人发言", false)
	default:
		a.appendFinding("enforce-secure-profile", raw, bindingReasonBadBoolean,
			"enforce-secure-profile 取值不是 true/false", false)
	}
}

func (a *ServerBindingAudit) auditProxyConnections(props *serverProperties) {
	raw, ok := props.Get("prevent-proxy-connections")
	if !ok {
		return
	}
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "true":
		return
	case "false":
		a.appendFinding("prevent-proxy-connections", raw, bindingReasonProxyAllowed,
			"允许通过代理/VPN 连接，可绕过基于源 IP 的封禁与限流", false)
	default:
		a.appendFinding("prevent-proxy-connections", raw, bindingReasonBadBoolean,
			"prevent-proxy-connections 取值不是 true/false", false)
	}
}

func (a *ServerBindingAudit) auditStatus(props *serverProperties) {
	statusRaw, ok := props.Get("enable-status")
	if !ok {
		return
	}
	if strings.ToLower(strings.TrimSpace(statusRaw)) != "true" {
		return
	}
	bindRaw, bindOK := props.Get("server-ip")
	if !bindOK {
		return
	}
	addr := strings.TrimSpace(bindRaw)
	if addr == "" || strings.EqualFold(addr, "0.0.0.0") || strings.EqualFold(addr, "*") {
		a.appendFinding("enable-status", statusRaw, bindingReasonStatusPublic,
			"状态查询对所有网卡开放，未授权主机可枚举版本、模组与在线玩家", false)
	}
}

func (a *ServerBindingAudit) auditNumericLimits(props *serverProperties) {
	if raw, ok := props.Get("network-compression-threshold"); ok {
		value := strings.TrimSpace(raw)
		if value != "" && value != "-1" && value != "0" {
			if n, valid := parseIntBounded(value, 0, 1<<20); !valid || n > 65536 {
				a.appendFinding("network-compression-threshold", raw, bindingReasonBadCompress,
					"压缩阈值超出合理范围，可能被用于制造 CPU 放大攻击", false)
			}
		}
	}
	if raw, ok := props.Get("max-players"); ok {
		value := strings.TrimSpace(raw)
		if n, valid := parseIntBounded(value, 1, 100000); !valid || n <= 0 {
			a.appendFinding("max-players", raw, bindingReasonBadPlayerCap,
				"max-players 不是 1 以上的整数", false)
		}
	}
	if raw, ok := props.Get("view-distance"); ok {
		value := strings.TrimSpace(raw)
		if n, valid := parseIntBounded(value, 2, 32); !valid {
			a.appendFinding("view-distance", raw, bindingReasonBadViewDist,
				"view-distance 超出 2~32，异常值会放大服务端负载", false)
		} else if n > 16 {
			a.appendFinding("view-distance", raw, bindingReasonBadViewDist,
				"view-distance 高于 16，会增加带宽与实体追踪压力", false)
		}
	}
}

func parseIntBounded(value string, min, max int) (int, bool) {
	if value == "" {
		return 0, false
	}
	negative := false
	start := 0
	if value[0] == '-' {
		negative = true
		start = 1
	}
	if start >= len(value) {
		return 0, false
	}
	n := 0
	for i := start; i < len(value); i++ {
		ch := value[i]
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int(ch-'0')
		if n > 1<<30 {
			return 0, false
		}
	}
	if negative {
		n = -n
	}
	if n < min || n > max {
		return n, false
	}
	return n, true
}
