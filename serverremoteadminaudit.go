package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
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
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *ServerRemoteAudit) HasWarnings() bool {
	return a != nil && len(a.Findings) > 0
}

func (a *ServerRemoteAudit) Codes() []string {
	if a == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(a.Findings))
	codes := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if _, ok := seen[f.Reason]; ok {
			continue
		}
		seen[f.Reason] = struct{}{}
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a *ServerRemoteAudit) Describe() string {
	if a == nil {
		return ""
	}
	if len(a.Findings) == 0 {
		return "server.properties 远程管理配置无风险"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s): %s", f.Key, f.Reason, f.Detail))
	}
	return strings.Join(parts, "; ")
}

func AuditServerRemoteAdmin(serverDir string) (*ServerRemoteAudit, error) {
	audit := &ServerRemoteAudit{
		Path:   filepath.Join(serverDir, "server.properties"),
		Values: map[string]string{},
	}
	info, err := os.Lstat(audit.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return audit, nil
		}
		return nil, fmt.Errorf("读取服务器配置失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Present = true
		audit.Findings = append(audit.Findings, RemoteFinding{
			Key: "server.properties", Reason: remoteReasonSymlink,
			Detail: "配置文件是符号链接，拒绝按远程管理配置审计", Blocking: true,
		})
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Present = true
		audit.Findings = append(audit.Findings, RemoteFinding{
			Key: "server.properties", Reason: remoteReasonNotRegular,
			Detail: "配置文件不是普通文件", Blocking: true,
		})
		return audit, nil
	}
	if info.Size() > remoteMaxBytes {
		audit.Present = true
		audit.Findings = append(audit.Findings, RemoteFinding{
			Key: "server.properties", Reason: remoteReasonTooLarge,
			Detail: fmt.Sprintf("配置文件超过 %d 字节上限", remoteMaxBytes), Blocking: true,
		})
		return audit, nil
	}
	data, err := os.ReadFile(audit.Path)
	if err != nil {
		return nil, fmt.Errorf("读取服务器配置失败: %w", err)
	}
	audit.Present = true
	props := parseServerProperties(data)
	for _, key := range remoteKeys {
		if value, ok := props.Get(key); ok {
			audit.Values[key] = value
		}
	}
	for key, count := range remoteKeyCounts(data) {
		if count > 1 {
			audit.add(key, "", remoteReasonDuplicateKey,
				fmt.Sprintf("同一配置键出现 %d 次，生效值取决于解析顺序", count), false)
		}
	}
	audit.auditRcon(props)
	audit.auditQuery(props)
	audit.auditIdentity(props)
	audit.auditBinding(props)
	audit.auditLimits(props)
	return audit, nil
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

func remoteKeyCounts(data []byte) map[string]int {
	counts := map[string]int{}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == '!' {
			continue
		}
		key, _, _, ok := splitPropertyPair(strings.TrimRight(line, "\r"))
		if !ok {
			continue
		}
		counts[key]++
	}
	return counts
}

func remoteBool(props *serverProperties, key string, fallback bool) bool {
	value, ok := props.Get(key)
	if !ok {
		return fallback
	}
	return remoteBoolValue(value, fallback)
}

func remoteBoolValue(value string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true
	case "false", "no", "off", "0":
		return false
	}
	return fallback
}

func remotePort(value string) (int, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

func remoteWeakPassword(value string) bool {
	lower := strings.ToLower(value)
	for _, weak := range remoteWeakPasswords {
		if lower == weak {
			return true
		}
	}
	return false
}

func remoteWildcardIP(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		return ip.IsUnspecified()
	}
	for _, wildcard := range remoteWildcardBindings {
		if value == wildcard {
			return true
		}
	}
	return false
}
