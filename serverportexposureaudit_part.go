package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func pxParseProperties(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		out[strings.ToLower(key)] = value
	}
	return out
}

func pxParsePort(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	if len(value) > 1 && value[0] == '0' {
		return 0, false
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	if port < 1 || port > 65535 {
		return port, false
	}
	return port, true
}

func pxIsBindAll(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if value == "0.0.0.0" || value == "::" || value == "[::]" || value == "*" {
		return true
	}
	return false
}

func pxIsWeakPassword(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return true
	}
	if len([]rune(normalized)) < pxMinPasswordLength {
		return true
	}
	for _, weak := range pxWeakPasswords {
		if normalized == weak {
			return true
		}
	}
	unique := map[rune]struct{}{}
	for _, r := range normalized {
		unique[r] = struct{}{}
	}
	if len(unique) <= 3 {
		return true
	}
	return false
}

func pxCheckPort(a *ServerPortAudit, props map[string]string, key string) int {
	raw := props[key]
	if strings.TrimSpace(raw) == "" {
		a.Ports[key] = 0
		return 0
	}
	port, ok := pxParsePort(raw)
	a.Ports[key] = port
	if !ok {
		a.add(pxReasonBadPort, fmt.Sprintf("%s=%q 不是合法端口", key, raw), true)
		return 0
	}
	if port < 1024 {
		a.add(pxReasonLowPort, fmt.Sprintf("%s=%d 落在特权端口区间", key, port), false)
	}
	if label, bad := pxForbiddenPorts[port]; bad {
		a.add(pxReasonPortConflict, fmt.Sprintf("%s=%d 与常见服务端口冲突: %s", key, port, label), false)
	}
	return port
}

func AuditServerPorts(serverDir string) ServerPortAudit {
	audit := ServerPortAudit{
		Dir:   serverDir,
		File:  filepath.Join(serverDir, "server.properties"),
		Ports: map[string]int{},
	}
	info, err := os.Lstat(audit.File)
	if err != nil || info.IsDir() {
		audit.add(pxReasonMissing, "缺少 server.properties", false)
		return audit
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(pxReasonSymlink, "server.properties 是符号链接", true)
		return audit
	}
	if info.Size() > pxMaxPropertiesBytes {
		audit.add(pxReasonTooLarge, "server.properties 超过体积预算", true)
		return audit
	}
	if info.Mode().Perm()&0o022 != 0 {
		audit.add(pxReasonWorldWritable, "server.properties 可被其他用户写入", true)
	}
	data, err := readBoundedFile(audit.File, pxMaxPropertiesBytes)
	if err != nil {
		audit.add(pxReasonUnreadable, "server.properties 不可读", true)
		return audit
	}
	props := pxParseProperties(string(data))
	audit.BindIP = strings.TrimSpace(props["server-ip"])
	if pxIsBindAll(audit.BindIP) {
		audit.add(pxReasonBindAll, "server-ip 未限制具体网卡，监听全部接口", false)
	}
	mainPort := pxCheckPort(&audit, props, "server-port")
	queryPort := pxCheckPort(&audit, props, "query.port")
	rconPort := pxCheckPort(&audit, props, "rcon.port")

	seen := map[int]string{}
	for _, key := range []string{"server-port", "query.port", "rcon.port"} {
		port := audit.Ports[key]
		if port == 0 {
			continue
		}
		if prev, dup := seen[port]; dup && prev != key {
			audit.add(pxReasonPortConflict, fmt.Sprintf("%s 与 %s 使用同一端口 %d", key, prev, port), true)
			continue
		}
		seen[port] = key
	}
	if mainPort != 0 && queryPort != 0 && props["enable-query"] == "true" {
		audit.add(pxReasonQueryOpen, fmt.Sprintf("查询协议对外开放（%d），且沿用默认端口族", queryPort), false)
	}
	if props["enable-rcon"] == "true" {
		password := props["rcon.password"]
		if strings.TrimSpace(password) == "" {
			audit.add(pxReasonRconOpen, "启用 rcon 却没有设置 rcon.password", true)
		} else if pxIsWeakPassword(password) {
			audit.add(pxReasonWeakPassword, "rcon.password 过弱或过短", true)
		}
		if pxIsBindAll(audit.BindIP) && rconPort != 0 {
			audit.add(pxReasonRconExposed, fmt.Sprintf("rcon 监听全部接口端口 %d", rconPort), true)
		}
	} else if strings.TrimSpace(props["rcon.password"]) != "" {
		audit.add(pxReasonStaleSecret, "rcon 已关闭但配置文件仍保留口令", false)
	}
	if strings.TrimSpace(props["prevent-proxy-connections"]) == "false" {
		audit.add(pxReasonProxyBypass, "prevent-proxy-connections=false 允许代理穿透", false)
	}
	if len(audit.Findings) == 0 {
		audit.add(pxReasonOK, "端口与绑定配置符合预期", false)
	}
	return audit
}
