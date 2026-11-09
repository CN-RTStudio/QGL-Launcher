package main

import (
	"strconv"
	"strings"
)

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
