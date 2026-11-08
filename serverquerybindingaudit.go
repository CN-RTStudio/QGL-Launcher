package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

type QueryBindingFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type QueryBindingAudit struct {
	ServerDir string
	Findings  []QueryBindingFinding
}

func (a *QueryBindingAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= sqbMaxFindings {
		return
	}
	a.Findings = append(a.Findings, QueryBindingFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *QueryBindingAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f QueryBindingFinding) bool { return f.Blocking })
}

func (a *QueryBindingAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if f.Reason != sqbReasonOK && !f.Blocking {
			return true
		}
	}
	return false
}

func (a *QueryBindingAudit) Describe() string {
	return describeFindings(a.Findings, func(f QueryBindingFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func sqbLoadText(a *QueryBindingAudit, root, rel string, maxBytes int64) (string, bool) {
	path := filepath.Join(root, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, sqbReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return "", false
	}
	data, err := readBoundedFile(path, maxBytes)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return "", false
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, sqbReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", maxBytes), true)
			return "", false
		}
		a.add(rel, sqbReasonUnread, "配置文件不可读", false)
		return "", false
	}
	return string(data), true
}

func sqbBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}

func sqbPort(props map[string]string, key string) (int, bool, bool) {
	return propsLookupInt(props, key)
}

func sqbIsWildcardHost(host string) bool {
	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0", "::", "[::]", "*":
		return true
	}
	return false
}

func sqbHostLooksInvalid(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.ContainsAny(host, "/\\") || strings.Contains(host, "://") {
		return true
	}
	if strings.ContainsAny(host, " \t") {
		return true
	}
	if strings.Contains(host, "@") || strings.Contains(host, "?") || strings.Contains(host, "#") {
		return true
	}
	return false
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

func AuditServerQueryBinding(serverDir string) *QueryBindingAudit {
	a := &QueryBindingAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", sqbReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sqbReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", sqbReasonMissing, "服务器目录不存在", false)
		return a
	}

	if text, ok := sqbLoadText(a, serverDir, "server.properties", sqbMaxProps); ok {
		props := pxParseProperties(text)
		if len(props) == 0 && strings.TrimSpace(text) != "" {
			a.add("server.properties", sqbReasonBadValue, "server.properties 未解析出任何键值", false)
		}
		sqbCheckQuery(a, props)
	}

	if text, ok := sqbLoadText(a, serverDir, "bukkit.yml", sqbMaxBukkit); ok {
		sqbCheckBukkit(a, cfgFlattenYAML(text))
	}

	return a
}
