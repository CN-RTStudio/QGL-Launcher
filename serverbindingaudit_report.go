package main

import (
	"strings"
)

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
