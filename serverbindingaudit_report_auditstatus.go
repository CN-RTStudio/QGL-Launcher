package main

import (
	"strings"
)

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
