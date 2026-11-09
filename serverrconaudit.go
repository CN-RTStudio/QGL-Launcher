package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	rconReasonOK             = "ok"
	rconReasonMissing        = "missing"
	rconReasonSymlink        = "symlink"
	rconReasonUnreadable     = "unreadable"
	rconReasonEmptyPassword  = "empty-rcon-password"
	rconReasonWeakPassword   = "weak-rcon-password"
	rconReasonBadPassword    = "bad-rcon-password"
	rconReasonBadPort        = "bad-rcon-port"
	rconReasonPortCollision  = "rcon-port-collision"
	rconReasonBroadcast      = "rcon-broadcast-to-ops"
	rconReasonQueryEnabled   = "query-enabled"
	rconReasonQueryPublic    = "query-public"
	rconReasonQueryPort      = "bad-query-port"
	rconReasonQueryCollision = "query-port-collision"
	rconReasonStalePassword  = "stale-rcon-password"
	rconReasonDuplicateKey   = "duplicate-key"
	rconMinPasswordRunes     = 8
	rconMaxPasswordRunes     = 256
)

type RconFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerRconAudit struct {
	Path     string
	Present  bool
	Findings []RconFinding
}

func (a *ServerRconAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f RconFinding) bool { return f.Blocking })
}

func (a *ServerRconAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != rconReasonOK {
			return true
		}
	}
	return false
}

func (a *ServerRconAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f RconFinding) string { return f.Reason })
}

func (a *ServerRconAudit) Describe() string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Key == "" {
			parts = append(parts, fmt.Sprintf("%s: %s", f.Reason, f.Detail))
			continue
		}
		if f.Value != "" {
			parts = append(parts, fmt.Sprintf("%s=%q(%s): %s", f.Key, f.Value, f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%s): %s", f.Key, f.Reason, f.Detail))
	}
	return strings.Join(parts, "；")
}

func AuditServerRcon(serverDir string) (*ServerRconAudit, error) {
	path := filepath.Join(serverDir, "server.properties")
	audit := &ServerRconAudit{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.Findings = append(audit.Findings, RconFinding{
				Reason: rconReasonMissing, Detail: "server.properties 不存在，无法审计 RCON/Query 暴露面",
			})
			return audit, nil
		}
		return nil, fmt.Errorf("读取 server.properties 属性失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, RconFinding{
			Reason: rconReasonSymlink, Detail: "server.properties 是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, RconFinding{
			Reason: rconReasonUnreadable, Detail: "server.properties 不是普通文件", Blocking: true,
		})
		return audit, nil
	}
	if info.Size() > int64(localTextConfigMaxBytes) {
		audit.Findings = append(audit.Findings, RconFinding{
			Reason: rconReasonUnreadable, Detail: "server.properties 体积异常，跳过审计", Blocking: true,
		})
		return audit, nil
	}
	data, err := readBoundedFile(path, int64(localTextConfigMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("读取 server.properties 失败: %w", err)
	}
	props := parseServerProperties(data)
	audit.Present = true
	audit.auditDuplicateKeys(props)
	audit.auditRcon(props)
	audit.auditQuery(props)
	return audit, nil
}

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
