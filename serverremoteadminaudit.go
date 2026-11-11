package main

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	remoteReasonOK            = "ok"
	remoteReasonMissing       = "missing"
	remoteReasonTooLarge      = "too-large"
	remoteReasonNotRegular    = "not-regular"
	remoteReasonSymlink       = "symlink"
	remoteReasonEmptyPassword = "empty-password"
	remoteReasonShortPassword = "short-password"
	remoteReasonWeakPassword  = "weak-password"
	remoteReasonBadPort       = "bad-port"
	remoteReasonPortConflict  = "port-conflict"
	remoteReasonQueryOpen     = "query-open"
	remoteReasonOfflineMode   = "offline-mode"
	remoteReasonEnforceOff    = "whitelist-not-enforced"
	remoteReasonBindAll       = "bind-all"
	remoteReasonProxyBypass   = "proxy-bypass"
	remoteReasonBroadcastOps  = "broadcast-rcon"
	remoteReasonDuplicateKey  = "duplicate-key"
	remoteReasonBadLimit      = "bad-players"

	remoteMaxBytes         = 1 << 20
	remoteMinPasswordRunes = 8
)

var remoteWeakPasswords = []string{
	"rcon", "password", "changeme", "change-me", "minecraft", "12345678",
	"123456789", "admin", "qwerty", "letmein", "secret", "test1234",
}

var remoteWildcardBindings = []string{"0.0.0.0", "::", "*", "[::]"}

var remoteKeys = []string{
	"enable-rcon", "rcon.password", "rcon.port", "broadcast-rcon-to-ops",
	"enable-query", "query.port", "online-mode", "white-list", "enforce-whitelist",
	"server-ip", "prevent-proxy-connections", "max-players",
}

type RemoteFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerRemoteAudit struct {
	Path     string
	Present  bool
	Values   map[string]string
	Findings []RemoteFinding
}

func (a *ServerRemoteAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f RemoteFinding) bool { return f.Blocking })
}

func (a *ServerRemoteAudit) HasWarnings() bool {
	return a != nil && len(a.Findings) > 0
}

func (a *ServerRemoteAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f RemoteFinding) string { return f.Reason })
}

func (a *ServerRemoteAudit) add(key, value, reason, detail string, blocking bool) {
	a.Findings = append(a.Findings, RemoteFinding{
		Key: key, Value: value, Reason: reason, Detail: detail, Blocking: blocking,
	})
}
func (a *ServerRemoteAudit) auditRcon(props *serverProperties) {
	if !remoteBool(props, "enable-rcon", false) {
		return
	}
	password, _ := props.Get("rcon.password")
	trimmed := strings.TrimSpace(password)
	switch {
	case trimmed == "":
		a.add("enable-rcon", "true", remoteReasonEmptyPassword,
			"RCON 已开启但没有设置密码，任何能连上端口的人都能执行服务器命令", true)
	case len([]rune(trimmed)) < remoteMinPasswordRunes:
		a.add("rcon.password", trimmed, remoteReasonShortPassword,
			fmt.Sprintf("RCON 密码少于 %d 个字符", remoteMinPasswordRunes), true)
	case remoteWeakPassword(trimmed):
		a.add("rcon.password", trimmed, remoteReasonWeakPassword,
			"RCON 密码属于常见弱口令", true)
	case strings.ContainsAny(trimmed, " \t"):
		a.add("rcon.password", trimmed, remoteReasonWeakPassword,
			"RCON 密码包含空白字符，容易被配置解析截断", true)
	}
	if port, ok := props.Get("rcon.port"); ok {
		if _, valid := remotePort(port); !valid {
			a.add("rcon.port", port, remoteReasonBadPort,
				"RCON 端口不是 1~65535 的整数", true)
		}
	}
	if remoteBool(props, "broadcast-rcon-to-ops", false) {
		a.add("broadcast-rcon-to-ops", "true", remoteReasonBroadcastOps,
			"RCON 命令会广播给所有 OP，扩大命令内容泄露面", false)
	}
}

func (a *ServerRemoteAudit) auditQuery(props *serverProperties) {
	if !remoteBool(props, "enable-query", false) {
		return
	}
	a.add("enable-query", "true", remoteReasonQueryOpen,
		"GameSpy 查询协议会向未认证请求暴露服务器版本与玩家列表", false)
	port, ok := props.Get("query.port")
	if !ok {
		return
	}
	if _, valid := remotePort(port); !valid {
		a.add("query.port", port, remoteReasonBadPort,
			"查询端口不是 1~65535 的整数", false)
	}
	if rconPort, ok := props.Get("rcon.port"); ok && rconPort == port && remoteBool(props, "enable-rcon", false) {
		a.add("query.port", port, remoteReasonPortConflict,
			"查询端口与 RCON 端口相同，可能被 UDP/TCP 混淆利用", false)
	}
}

func (a *ServerRemoteAudit) auditIdentity(props *serverProperties) {
	if value, ok := props.Get("online-mode"); ok && !remoteBoolValue(value, true) {
		a.add("online-mode", value, remoteReasonOfflineMode,
			"离线模式不校验 Mojang 会话，玩家可冒用任意用户名与 UUID", false)
	}
	if remoteBool(props, "white-list", false) && !remoteBool(props, "enforce-whitelist", false) {
		a.add("enforce-whitelist", "false", remoteReasonEnforceOff,
			"白名单已开启但未强制，名单变更后已在线的非白名单玩家不会被踢出", false)
	}
	if value, ok := props.Get("prevent-proxy-connections"); ok && !remoteBoolValue(value, true) {
		a.add("prevent-proxy-connections", value, remoteReasonProxyBypass,
			"允许代理连接后，玩家可用代理伪造来源 IP 绕过封禁", false)
	}
}

func (a *ServerRemoteAudit) auditBinding(props *serverProperties) {
	ip, ok := props.Get("server-ip")
	if !ok {
		return
	}
	trimmed := strings.TrimSpace(ip)
	if trimmed == "" || remoteWildcardIP(trimmed) {
		a.add("server-ip", ip, remoteReasonBindAll,
			"显式绑定通配地址，服务器会监听所有网卡", false)
	}
}

func (a *ServerRemoteAudit) auditLimits(props *serverProperties) {
	raw, ok := props.Get("max-players")
	if !ok {
		return
	}
	limit, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || limit <= 0 || limit > 100000 {
		a.add("max-players", raw, remoteReasonBadLimit,
			"玩家上限不是有效正整数", false)
	}
}
