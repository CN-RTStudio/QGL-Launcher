package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	pfwMaxFindings            = 48
	pfwMaxProps               = 256 * 1024
	pfwMaxYAML                = 512 * 1024
	pfwMinSecretLen           = 32
	pfwReasonOK               = "ok"
	pfwReasonMissing          = "missing"
	pfwReasonSymlink          = "symlink"
	pfwReasonTooLarge         = "too-large"
	pfwReasonBadValue         = "bad-value"
	pfwReasonOffline          = "offline-mode"
	pfwReasonOfflineExposed   = "offline-mode-exposed"
	pfwReasonWeakSecret       = "weak-proxy-secret"
	pfwReasonLegacyBungee     = "legacy-bungee-forwarding"
	pfwReasonConflict         = "conflicting-proxy-mode"
	pfwReasonUncheckedForward = "unchecked-forwarding"
	pfwReasonProxyOnline      = "proxy-offline-mode"
	pfwReasonUnreadable       = "unreadable"
	pfwReasonBadConfig        = "bad-config"
)

type ProxyForwardFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type ProxyForwardAudit struct {
	ServerDir string
	ProxyKind string
	Findings  []ProxyForwardFinding
}

func (a *ProxyForwardAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= pfwMaxFindings {
		return
	}
	a.Findings = append(a.Findings, ProxyForwardFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *ProxyForwardAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ProxyForwardFinding) bool { return f.Blocking })
}

func (a *ProxyForwardAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if f.Reason != pfwReasonOK && !f.Blocking {
			return true
		}
	}
	return false
}

func (a *ProxyForwardAudit) Describe() string {
	return describeFindings(a.Findings, func(f ProxyForwardFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func pfwLoadText(a *ProxyForwardAudit, root, rel string, maxBytes int64) (string, bool) {
	path := filepath.Join(root, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, pfwReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return "", false
	}
	data, err := readBoundedFile(path, maxBytes)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return "", false
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, pfwReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", maxBytes), true)
			return "", false
		}
		a.add(rel, pfwReasonUnreadable, "配置文件不可读", false)
		return "", false
	}
	return string(data), true
}

func pfwPropBool(props map[string]string, key string) (bool, bool) {
	value, ok := props[key]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	return false, false
}

func pfwCheckProperties(a *ProxyForwardAudit, props map[string]string) {
	onlineMode, onlineKnown := pfwPropBool(props, "online-mode")
	preventProxy, preventKnown := pfwPropBool(props, "prevent-proxy-connections")
	enforceSecure, secureKnown := pfwPropBool(props, "enforce-secure-profile")

	if !onlineKnown {
		a.add("server.properties", pfwReasonMissing, "缺少 online-mode 声明，按默认在线模式处理", false)
	} else if !onlineMode {
		a.add("server.properties", pfwReasonOffline, "online-mode=false，未启用 Mojang 校验", false)
	}
	if preventKnown && !preventProxy {
		a.add("server.properties", pfwReasonUncheckedForward, "prevent-proxy-connections=false，代理可透传任意来源 IP", false)
	}
	if secureKnown && !enforceSecure {
		a.add("server.properties", pfwReasonUncheckedForward, "enforce-secure-profile=false，聊天签名可被剥离", false)
	}
}

func pfwCheckSpigot(a *ProxyForwardAudit, flat map[string]string) {
	bungee, ok := cfgLookup(flat, "settings.bungeecord")
	if !ok {
		return
	}
	switch strings.ToLower(strings.TrimSpace(bungee)) {
	case "true":
		a.add("spigot.yml", pfwReasonLegacyBungee, "settings.bungeecord=true，BungeeCord 转发无共享密钥，任意来源可伪造玩家身份", true)
	case "false":
	case "":
		a.add("spigot.yml", pfwReasonBadValue, "settings.bungeecord 没有取值", false)
	default:
		a.add("spigot.yml", pfwReasonBadValue, "settings.bungeecord 取值非法: "+bungee, false)
	}
	timeout, ok := cfgLookup(flat, "settings.restart-on-crash")
	if ok {
		switch strings.ToLower(strings.TrimSpace(timeout)) {
		case "true", "false":
		default:
			a.add("spigot.yml", pfwReasonBadValue, "settings.restart-on-crash 取值非法: "+timeout, false)
		}
	}
}

func pfwCheckPaperProxy(a *ProxyForwardAudit, flat map[string]string) {
	velocityEnabled, hasVelocity := cfgLookup(flat, "proxies.velocity.enabled")
	bungeeEnabled, hasBungee := cfgLookup(flat, "proxies.bungee-cord.enabled")

	velocityOn := strings.EqualFold(strings.TrimSpace(velocityEnabled), "true")
	bungeeOn := strings.EqualFold(strings.TrimSpace(bungeeEnabled), "true")

	if hasVelocity && velocityOn {
		a.ProxyKind = "velocity"
		secret, hasSecret := cfgLookup(flat, "proxies.velocity.secret")
		if !hasSecret || cfgIsPlaceholder(secret) {
			a.add("config/paper-global.yml", pfwReasonWeakSecret, "Velocity 转发密钥缺失或为占位值", true)
		} else if len(secret) < pfwMinSecretLen {
			a.add("config/paper-global.yml", pfwReasonWeakSecret, fmt.Sprintf("Velocity 转发密钥长度 %d 低于 %d", len(secret), pfwMinSecretLen), true)
		}
		if cfgHasControlChars(secret) {
			a.add("config/paper-global.yml", pfwReasonBadValue, "Velocity 转发密钥包含控制字符", true)
		}
		if onlineMode, ok := cfgLookup(flat, "proxies.velocity.online-mode"); ok && !strings.EqualFold(strings.TrimSpace(onlineMode), "true") {
			a.add("config/paper-global.yml", pfwReasonProxyOnline, "proxies.velocity.online-mode=false，代理端未做正版校验", false)
		}
	}
	if hasBungee && bungeeOn {
		a.ProxyKind = "bungeecord"
		if onlineMode, ok := cfgLookup(flat, "proxies.bungee-cord.online-mode"); ok && !strings.EqualFold(strings.TrimSpace(onlineMode), "true") {
			a.add("config/paper-global.yml", pfwReasonProxyOnline, "proxies.bungee-cord.online-mode=false，代理端未做正版校验", false)
		}
		a.add("config/paper-global.yml", pfwReasonLegacyBungee, "proxies.bungee-cord.enabled=true，使用无密钥的旧式转发", false)
	}
	if velocityOn && bungeeOn {
		a.add("config/paper-global.yml", pfwReasonConflict, "Velocity 与 BungeeCord 转发同时启用", true)
	}
}

func pfwCheckCrossSource(a *ProxyForwardAudit, props map[string]string, flat map[string]string) {
	onlineMode, known := pfwPropBool(props, "online-mode")
	if !known || onlineMode {
		return
	}
	proxyOff := true
	if value, ok := cfgLookup(flat, "proxies.velocity.enabled"); ok && strings.EqualFold(strings.TrimSpace(value), "true") {
		proxyOff = false
	}
	if value, ok := cfgLookup(flat, "proxies.bungee-cord.enabled"); ok && strings.EqualFold(strings.TrimSpace(value), "true") {
		proxyOff = false
	}
	if value, ok := cfgLookup(flat, "settings.bungeecord"); ok && strings.EqualFold(strings.TrimSpace(value), "true") {
		proxyOff = false
	}
	if proxyOff {
		a.add("server.properties", pfwReasonOfflineExposed, "online-mode=false 且未启用任何受信任代理转发配置，UUID 可被伪造", true)
	}
}

func AuditServerProxyForwarding(serverDir string) *ProxyForwardAudit {
	a := &ProxyForwardAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", pfwReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", pfwReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", pfwReasonMissing, "服务器目录不存在", false)
		return a
	}

	props := map[string]string{}
	if text, ok := pfwLoadText(a, serverDir, "server.properties", pfwMaxProps); ok {
		props = pxParseProperties(text)
		if len(props) == 0 && strings.TrimSpace(text) != "" {
			a.add("server.properties", pfwReasonBadConfig, "server.properties 未解析出任何键值", false)
		}
		pfwCheckProperties(a, props)
	}

	spigotFlat := map[string]string{}
	if text, ok := pfwLoadText(a, serverDir, "spigot.yml", pfwMaxYAML); ok {
		spigotFlat = cfgFlattenYAML(text)
		if len(spigotFlat) == 0 && strings.TrimSpace(text) != "" {
			a.add("spigot.yml", pfwReasonBadConfig, "spigot.yml 未解析出任何键值", false)
		}
	}

	paperFlat := map[string]string{}
	if text, ok := pfwLoadText(a, serverDir, "config/paper-global.yml", pfwMaxYAML); ok {
		paperFlat = cfgFlattenYAML(text)
		if len(paperFlat) == 0 && strings.TrimSpace(text) != "" {
			a.add("config/paper-global.yml", pfwReasonBadConfig, "paper-global.yml 未解析出任何键值", false)
		}
	}

	pfwCheckSpigot(a, spigotFlat)
	pfwCheckPaperProxy(a, paperFlat)
	if len(props) > 0 {
		pfwCheckCrossSource(a, props, paperFlat)
	}

	if len(props) == 0 && len(spigotFlat) == 0 && len(paperFlat) == 0 {
		a.add(".", pfwReasonMissing, "未发现代理或在线模式配置", false)
	}
	return a
}
