package main

import (
	"fmt"
)

const (
	sqbMaxFindings    = 40
	sqbMaxProps       = 256 * 1024
	sqbMaxBukkit      = 512 * 1024
	sqbReasonOK       = "ok"
	sqbReasonMissing  = "missing"
	sqbReasonSymlink  = "symlink"
	sqbReasonTooLarge = "too-large"
	sqbReasonUnread   = "unreadable"
	sqbReasonBadValue = "bad-value"
	sqbReasonQueryOn  = "query-enabled"
	sqbReasonBindAll  = "query-bind-all"
	sqbReasonPortLow  = "query-port-privileged"
	sqbReasonPortZero = "query-port-zero"
	sqbReasonOrphan   = "query-port-orphaned"
	sqbReasonHostPath = "server-ip-not-address"
	sqbReasonStatus   = "status-disabled"
	sqbReasonCollide  = "query-rcon-port-collision"
)

type QueryBindingFinding = auditFinding
type QueryBindingAudit struct {
	ServerDir string
	Findings  []QueryBindingFinding
}

func (a *QueryBindingAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sqbMaxFindings, QueryBindingFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *QueryBindingAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f QueryBindingFinding) bool { return f.Blocking })
}
func (a *QueryBindingAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f QueryBindingFinding) bool { return f.Reason != sqbReasonOK && !f.Blocking })
}

func sqbCheckQuery(a *QueryBindingAudit, props map[string]string) {
	queryOn, queryKnown := sqbBool(props, "enable-query")
	if queryKnown && queryOn {
		a.add("server.properties", sqbReasonQueryOn, "enable-query=true，GS4 查询协议对外暴露在线玩家与插件列表", false)
	}

	queryPort, portKnown, portValid := sqbPort(props, "query.port")
	if portKnown {
		switch {
		case !portValid:
			a.add("server.properties", sqbReasonBadValue, "query.port 不是合法整数", false)
		case queryPort == 0:
			a.add("server.properties", sqbReasonPortZero, "query.port=0，查询服务端口未固定", true)
		case queryPort < 1024:
			a.add("server.properties", sqbReasonPortLow, fmt.Sprintf("query.port=%d 属于特权端口", queryPort), true)
		case queryPort > 65535:
			a.add("server.properties", sqbReasonBadValue, fmt.Sprintf("query.port=%d 超出 65535", queryPort), false)
		}
		if queryKnown && !queryOn {
			a.add("server.properties", sqbReasonOrphan, "enable-query=false 但仍声明了 query.port", false)
		}
	}

	rconPort, rconKnown, rconValid := sqbPort(props, "rcon.port")
	if rconKnown && rconValid && portKnown && portValid && rconPort == queryPort {
		a.add("server.properties", sqbReasonCollide, fmt.Sprintf("query.port 与 rcon.port 同为 %d，端口规划冲突", queryPort), false)
	}

	host := props["server-ip"]
	if sqbHostLooksInvalid(host) {
		a.add("server.properties", sqbReasonHostPath, "server-ip 不是合法地址: "+host, true)
	}
	if queryKnown && queryOn && sqbIsWildcardHost(host) {
		a.add("server.properties", sqbReasonBindAll, "enable-query=true 且未绑定具体地址，查询服务监听全部网卡", false)
	}

	statusOn, statusKnown := sqbBool(props, "enable-status")
	if statusKnown && !statusOn {
		a.add("server.properties", sqbReasonStatus, "enable-status=false，服务端不再响应状态列表请求", false)
	}
}

func sqbCheckBukkit(a *QueryBindingAudit, flat map[string]string) {
	if value, ok := cfgLookup(flat, "settings.query-plugins"); ok {
		on, known := spxBool(value)
		if !known {
			a.add("bukkit.yml", sqbReasonBadValue, "settings.query-plugins 取值非法: "+value, false)
		} else if on {
			a.add("bukkit.yml", sqbReasonQueryOn, "settings.query-plugins=true，查询响应包含全部插件版本", false)
		}
	}
	if value, ok := cfgLookup(flat, "settings.connection-throttle"); ok {
		n, valid := cfgParseInt(value)
		if !valid {
			a.add("bukkit.yml", sqbReasonBadValue, "settings.connection-throttle 取值非法: "+value, false)
		} else if n < 0 {
			a.add("bukkit.yml", sqbReasonBadValue, fmt.Sprintf("settings.connection-throttle=%d 为负值，连接节流被关闭", n), false)
		}
	}
}
