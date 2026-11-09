package main

import (
	"fmt"
	"strings"
)

func (a *ServerRconAudit) auditDuplicateKeys(props *serverProperties) {
	counts := make(map[string]int, len(props.lines))
	for _, line := range props.lines {
		if line.isPair {
			counts[line.key]++
		}
	}
	for key, count := range counts {
		if count < 2 {
			continue
		}
		a.Findings = append(a.Findings, RconFinding{
			Key: key, Reason: rconReasonDuplicateKey,
			Detail: fmt.Sprintf("键出现 %d 次，生效值不确定", count),
		})
	}
}

func (a *ServerRconAudit) auditRcon(props *serverProperties) {
	enabledRaw, enabledOK := props.Get("enable-rcon")
	enabled := enabledOK && strings.EqualFold(strings.TrimSpace(enabledRaw), "true")
	passwordRaw, passwordOK := props.Get("rcon.password")
	password := strings.TrimSpace(passwordRaw)
	serverPort, serverPortOK := props.Get("server-port")

	if !enabled {
		if passwordOK && password != "" {
			a.Findings = append(a.Findings, RconFinding{
				Key: "rcon.password", Reason: rconReasonStalePassword,
				Detail: "RCON 已关闭但配置文件仍保留口令，可能随备份/仓库泄露",
			})
		}
		return
	}

	if !passwordOK || password == "" {
		a.Findings = append(a.Findings, RconFinding{
			Key: "rcon.password", Reason: rconReasonEmptyPassword,
			Detail: "启用 RCON 却没有设置口令，任何能连到端口的进程都可执行服务器命令", Blocking: true,
		})
	} else {
		runes := []rune(password)
		if len(runes) < rconMinPasswordRunes {
			a.Findings = append(a.Findings, RconFinding{
				Key: "rcon.password", Reason: rconReasonWeakPassword,
				Detail: fmt.Sprintf("RCON 口令仅 %d 个字符，低于 %d 位下限", len(runes), rconMinPasswordRunes),
			})
		}
		if len(runes) > rconMaxPasswordRunes || containsControlByte(password) || strings.ContainsAny(password, " \t") {
			a.Findings = append(a.Findings, RconFinding{
				Key: "rcon.password", Reason: rconReasonBadPassword,
				Detail: "RCON 口令含空白/控制字符或长度超限", Blocking: true,
			})
		}
	}

	if broadcastRaw, ok := props.Get("broadcast-rcon-to-ops"); ok {
		if strings.EqualFold(strings.TrimSpace(broadcastRaw), "true") {
			a.Findings = append(a.Findings, RconFinding{
				Key: "broadcast-rcon-to-ops", Reason: rconReasonBroadcast,
				Detail: "RCON 命令会广播给所有 OP，命令内容可能泄露给非授权玩家",
			})
		}
	}

	a.auditPortPair(props, "rcon.port", "25575", serverPort, serverPortOK, rconReasonBadPort, rconReasonPortCollision)
}
