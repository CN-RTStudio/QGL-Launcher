package main

import "fmt"

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
