package main

import (
	"fmt"
	"strings"
)

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
