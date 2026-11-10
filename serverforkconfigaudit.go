package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	fkReasonOK              = "ok"
	fkReasonMissing         = "missing-all"
	fkReasonSymlink         = "symlink"
	fkReasonTooLarge        = "too-large"
	fkReasonWorldWritable   = "world-writable"
	fkReasonUnreadable      = "unreadable"
	fkReasonThrottleOff     = "connection-throttle-off"
	fkReasonLegacyProxy     = "legacy-proxy-enabled"
	fkReasonProxySecret     = "proxy-secret-missing"
	fkReasonXrayOff         = "anti-xray-off"
	fkReasonPacketLimiter   = "packet-limiter-off"
	fkReasonPacketRate      = "max-packet-rate-high"
	fkReasonCollisions      = "max-entity-collisions-high"
	fkReasonActivationRange = "activation-range-high"
	fkReasonViewDistance    = "view-distance-high"
	fkReasonSaveInterval    = "autosave-interval-high"
	fkReasonIdleTimeout     = "idle-timeout-zero"
	fkReasonUnknownValue    = "non-numeric-value"

	fkMaxConfigBytes = 2 << 20
	fkMaxFindings    = 48
)

var fkConfigFiles = []string{
	"bukkit.yml",
	"spigot.yml",
	"paper.yml",
	"config/paper-global.yml",
	"config/paper-world-defaults.yml",
}

type ForkConfigFinding = auditFinding

type ForkConfigAudit struct {
	Dir      string
	Files    []string
	Findings []ForkConfigFinding
}

func (a ForkConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ForkConfigFinding) bool { return f.Blocking })
}

func (a ForkConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ForkConfigFinding) bool { return !f.Blocking && f.Reason != fkReasonOK })
}

func fkNumber(props map[string]string, key string) (int, bool) {
	for _, candidate := range fkKeyVariants(key) {
		raw, ok := props[candidate]
		if !ok {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(strings.Trim(raw, `"'`)))
		if err != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}
func fkBool(props map[string]string, key string) (bool, bool) {
	for _, candidate := range fkKeyVariants(key) {
		raw, ok := props[candidate]
		if !ok {
			continue
		}
		normalized := strings.ToLower(strings.TrimSpace(strings.Trim(raw, `"'`)))
		switch normalized {
		case "true", "yes", "on":
			return true, true
		case "false", "no", "off":
			return false, true
		}
		return false, false
	}
	return false, false
}
func fkString(props map[string]string, key string) (string, bool) {
	for _, candidate := range fkKeyVariants(key) {
		raw, ok := props[candidate]
		if !ok {
			continue
		}
		return strings.Trim(strings.TrimSpace(raw), `"'`), true
	}
	return "", false
}

func fkKeyVariants(key string) []string {
	normalized := strings.ToLower(key)
	return []string{
		normalized,
		"settings." + normalized,
		"world-settings.default." + normalized,
		"world-settings.default." + normalized,
	}
}

func fkInspectFile(a *ForkConfigAudit, dir, name string) bool {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	a.Files = append(a.Files, name)
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(name, fkReasonSymlink, "分支配置文件是符号链接", true)
		return true
	}
	if info.Size() > fkMaxConfigBytes {
		a.add(name, fkReasonTooLarge, "分支配置文件超过体积预算", true)
		return true
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(name, fkReasonWorldWritable, "分支配置文件可被其他用户改写", true)
	}
	data, readErr := readBoundedFile(path, fkMaxConfigBytes)
	if readErr != nil {
		a.add(name, fkReasonUnreadable, "分支配置文件不可读", true)
		return true
	}
	fkScanText(a, name, string(data))
	return true
}

func fkScanText(a *ForkConfigAudit, name, text string) {
	props := fkFlattenConfig(text)
	if len(props) == 0 {
		return
	}
	if value, ok := fkNumber(props, "connection-throttle"); ok && value < 0 {
		a.add(name, fkReasonThrottleOff, "连接节流被关闭，登录洪水不限速", false)
	}
	if enabled, ok := fkBool(props, "settings.bungeecord"); ok && enabled {
		a.add(name, fkReasonLegacyProxy, "启用旧版 BungeeCord 代理转发", false)
	}
	if enabled, ok := fkBool(props, "bungeecord"); ok && enabled {
		a.add(name, fkReasonLegacyProxy, "启用旧版 BungeeCord 代理转发", false)
	}
	if value, ok := fkString(props, "settings.velocity-support.secret"); ok && value == "" {
		a.add(name, fkReasonProxySecret, "Velocity 转发密钥为空", true)
	}
	if forwarding, ok := fkBool(props, "settings.velocity-support.enabled"); ok && forwarding {
		if value, has := fkString(props, "settings.velocity-support.secret"); !has || len(value) < 16 {
			a.add(name, fkReasonProxySecret, "Velocity 转发密钥缺失或过短", true)
		}
	}
	if enabled, ok := fkBool(props, "anti-xray.enabled"); ok && !enabled {
		a.add(name, fkReasonXrayOff, "反矿透被关闭", false)
	}
	if enabled, ok := fkBool(props, "packet-limiter.enabled"); ok && !enabled {
		a.add(name, fkReasonPacketLimiter, "数据包限流被关闭", false)
	}
	if value, ok := fkNumber(props, "packet-limiter.max-packet-rate"); ok && value > 500 {
		a.add(name, fkReasonPacketRate, fmt.Sprintf("数据包速率上限 %d 过高", value), false)
	}
	if value, ok := fkNumber(props, "max-entity-collisions"); ok && value > 8 {
		a.add(name, fkReasonCollisions, fmt.Sprintf("实体碰撞上限 %d 过高", value), false)
	}
	if value, ok := fkNumber(props, "entity-activation-range.animals"); ok && value > 32 {
		a.add(name, fkReasonActivationRange, fmt.Sprintf("动物激活范围 %d 过大", value), false)
	}
	if value, ok := fkNumber(props, "view-distance"); ok && value > 12 {
		a.add(name, fkReasonViewDistance, fmt.Sprintf("视野距离 %d 超过推荐上限", value), false)
	}
	if value, ok := fkNumber(props, "ticks-per.autosave"); ok && value > 6000 {
		a.add(name, fkReasonSaveInterval, fmt.Sprintf("自动保存间隔 %d tick 过长", value), false)
	}
	if value, ok := fkNumber(props, "timeout-time"); ok && value <= 0 {
		a.add(name, fkReasonIdleTimeout, "空闲超时被关闭", false)
	}
	for key, raw := range props {
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "http:") {
			a.add(name, fkReasonUnknownValue, fmt.Sprintf("配置项 %s 使用明文 http 地址", key), false)
		}
	}
}

func AuditServerForkConfig(serverDir string) ForkConfigAudit {
	audit := ForkConfigAudit{Dir: serverDir}
	root, err := filepath.Abs(serverDir)
	if err != nil {
		audit.add("server-dir", fkReasonUnreadable, "无法解析服务器目录", true)
		return audit
	}
	audit.Dir = root
	info, statErr := os.Lstat(root)
	if statErr != nil || !info.IsDir() {
		audit.add("server-dir", fkReasonMissing, "服务器目录不存在", true)
		return audit
	}
	found := false
	for _, name := range fkConfigFiles {
		if fkInspectFile(&audit, root, name) {
			found = true
		}
	}
	if !found {
		audit.add("fork-config", fkReasonOK, "未使用分支配置文件", false)
		return audit
	}
	if len(audit.Findings) == 0 {
		audit.add("fork-config", fkReasonOK, "分支配置未发现风险", false)
	}
	return audit
}

func (a ForkConfigAudit) Describe() string {
	return describeTaggedFindings("服务端分支配置未发现风险", a.Findings, fkReasonOK, "fork-config", fkMaxFindings,
		func(f ForkConfigFinding) string { return f.Reason },
		func(f ForkConfigFinding) string { return f.File },
		func(f ForkConfigFinding) string { return f.Detail })
}
func (a *ForkConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, fkMaxFindings, ForkConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func fkFlattenConfig(text string) map[string]string {
	props := map[string]string{}
	stackKeys := []string{}
	stackIndent := []int{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		for len(stackIndent) > 0 && indent <= stackIndent[len(stackIndent)-1] {
			stackIndent = stackIndent[:len(stackIndent)-1]
			stackKeys = stackKeys[:len(stackKeys)-1]
		}
		colon := strings.Index(trimmed, ":")
		if colon <= 0 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(trimmed[:colon]), `"'`)
		value := strings.TrimSpace(trimmed[colon+1:])
		if key == "" {
			continue
		}
		if strings.HasPrefix(value, "#") {
			continue
		}
		if value == "" {
			stackIndent = append(stackIndent, indent)
			stackKeys = append(stackKeys, strings.ToLower(key))
			continue
		}
		parts := append(append([]string{}, stackKeys...), strings.ToLower(key))
		props[strings.Join(parts, ".")] = value
	}
	return props
}
