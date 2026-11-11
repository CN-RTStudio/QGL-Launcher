package main

import (
	"net"
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
	return auditHasWarning(a.Findings, func(f BindingFinding) bool { return !f.Blocking && f.Reason != bindingReasonOK })
}

func (a *ServerBindingAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodesSkip(a.Findings, bindingReasonOK, func(f BindingFinding) string { return f.Reason })
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
