package main

import (
	"fmt"
	"strings"
)

func (a *ServerRconAudit) auditQuery(props *serverProperties) {
	enabledRaw, ok := props.Get("enable-query")
	if !ok || !strings.EqualFold(strings.TrimSpace(enabledRaw), "true") {
		return
	}
	a.Findings = append(a.Findings, RconFinding{
		Key: "enable-query", Reason: rconReasonQueryEnabled,
		Detail: "GameSpy Query 开放后会向未授权主机泄露版本、模组与在线玩家列表",
	})

	bindRaw, bindOK := props.Get("server-ip")
	if bindOK {
		addr := strings.TrimSpace(bindRaw)
		if addr == "" || strings.EqualFold(addr, "0.0.0.0") || strings.EqualFold(addr, "*") {
			a.Findings = append(a.Findings, RconFinding{
				Key: "server-ip", Reason: rconReasonQueryPublic,
				Detail: "服务端监听通配地址且 Query 开启，公网可直接枚举玩家信息",
			})
		}
	}

	serverPort, serverPortOK := props.Get("server-port")
	a.auditPortPair(props, "query.port", "25565", serverPort, serverPortOK, rconReasonQueryPort, rconReasonQueryCollision)
}

func (a *ServerRconAudit) auditPortPair(props *serverProperties, key, defaultPort, serverPort string, serverPortOK bool, badReason, collisionReason string) {
	raw, ok := props.Get(key)
	portText := defaultPort
	if ok {
		portText = strings.TrimSpace(raw)
	}
	port, valid := parseIntBounded(portText, 1, 65535)
	if !valid {
		a.Findings = append(a.Findings, RconFinding{
			Key: key, Value: portText, Reason: badReason,
			Detail: "端口不是 1~65535 的整数", Blocking: true,
		})
		return
	}
	if !serverPortOK {
		return
	}
	server, validServer := parseIntBounded(strings.TrimSpace(serverPort), 1, 65535)
	if !validServer || server != port {
		return
	}
	a.Findings = append(a.Findings, RconFinding{
		Key: key, Value: portText, Reason: collisionReason,
		Detail: fmt.Sprintf("与管理端口 server-port=%d 相同，两条服务会争抢同一端口", server),
	})
}

func (a *ServerRconAudit) Summary() string {
	if !a.Present {
		return "RCON/Query 策略未审计"
	}
	if len(a.Findings) == 0 {
		return "RCON/Query 暴露面校验通过"
	}
	return a.Describe()
}
