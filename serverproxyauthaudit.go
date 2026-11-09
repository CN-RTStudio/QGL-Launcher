package main

import (
	"os"
	"strings"
)

const (
	spaMaxFindings      = 40
	spaMaxProps         = 256 * 1024
	spaMaxYAML          = 512 * 1024
	spaMinSecretLength  = 12
	spaReasonOK         = "ok"
	spaReasonMissing    = "missing"
	spaReasonSymlink    = "symlink"
	spaReasonTooLarge   = "too-large"
	spaReasonUnreadable = "unreadable"
	spaReasonBadValue   = "bad-value"
	spaReasonOffline    = "offline-mode-with-proxy"
	spaReasonPreventOff = "proxy-connection-prevention-off"
	spaReasonLegacy     = "bungeecord-legacy-forwarding"
	spaReasonNoPaper    = "bungeecord-without-paper-proxy"
	spaReasonNoSecret   = "velocity-secret-missing"
	spaReasonWeak       = "velocity-secret-weak"
	spaReasonSecretBad  = "velocity-secret-invalid"
	spaReasonProxyOff   = "proxy-online-mode-off"
	spaReasonNoToken    = "bungeeguard-token-missing"
	spaReasonTokenWeak  = "bungeeguard-token-weak"
	spaReasonDualProxy  = "dual-proxy-enabled"
)

type ProxyAuthFinding = auditFinding

type ProxyAuthAudit struct {
	ServerDir string
	Findings  []ProxyAuthFinding
}

func (a *ProxyAuthAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spaMaxFindings, ProxyAuthFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *ProxyAuthAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ProxyAuthFinding) bool { return f.Blocking })
}

func (a *ProxyAuthAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *ProxyAuthAudit) Describe() string {
	return describeAuditFindings("代理转发配置未发现风险", a.Findings, 12,
		func(f ProxyAuthFinding) []string {
			return []string{f.File, f.Reason}
		},
		func(f ProxyAuthFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func spaLoadText(a *ProxyAuthAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func spaBool(flat map[string]string, path string) (bool, bool) {
	return flatBoolValue(flat, path)
}

func spaText(flat map[string]string, path string) (string, bool) {
	value, ok := cfgLookup(flat, path)
	if !ok {
		return "", false
	}
	return cfgStripQuotes(value), true
}

func spaSecretProblem(secret string) string {
	if cfgHasControlChars(secret) {
		return spaReasonSecretBad
	}
	if cfgIsPlaceholder(secret) {
		return spaReasonNoSecret
	}
	if len(secret) < spaMinSecretLength {
		return spaReasonWeak
	}
	return ""
}

func AuditServerProxyAuth(serverDir string) *ProxyAuthAudit {
	a := &ProxyAuthAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", spaReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", spaReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", spaReasonMissing, "服务器目录不存在", false)
		return a
	}

	onlineMode := true
	if text, ok := spaLoadText(a, serverDir, "server.properties", spaMaxProps); ok {
		props := pxParseProperties(text)
		if value, found := props["online-mode"]; found {
			onlineMode = strings.EqualFold(strings.TrimSpace(value), "true")
		}
		if value, found := props["prevent-proxy-connections"]; found {
			if strings.EqualFold(strings.TrimSpace(value), "false") {
				a.add("server.properties", spaReasonPreventOff, "prevent-proxy-connections 已关闭", false)
			}
		}
	}

	spigotLegacy := false
	spigotToken := ""
	if text, ok := spaLoadText(a, serverDir, "spigot.yml", spaMaxYAML); ok {
		flat := cfgFlattenYAML(text)
		if enabled, found := spaBool(flat, "settings.bungeecord"); found && enabled {
			spigotLegacy = true
			a.add("spigot.yml", spaReasonLegacy, "启用 legacy BungeeCord 转发", false)
		}
		if token, found := spaText(flat, "settings.bungeeguard-token"); found {
			spigotToken = token
		}
	}

	paperLoaded := false
	if text, ok := spaLoadText(a, serverDir, "config/paper-global.yml", spaMaxYAML); ok {
		paperLoaded = true
		flat := cfgFlattenYAML(text)
		velocityOn, hasVelocity := spaBool(flat, "proxies.velocity.enabled")
		bungeeOn, hasBungee := spaBool(flat, "proxies.bungee-cord.enabled")
		if hasVelocity && velocityOn {
			a.add("config/paper-global.yml", spaReasonDualProxy, "启用 Velocity 转发", false)
			secret, found := spaText(flat, "proxies.velocity.secret")
			if !found || strings.TrimSpace(secret) == "" {
				a.add("config/paper-global.yml", spaReasonNoSecret, "proxies.velocity.secret 为空", true)
			} else if problem := spaSecretProblem(secret); problem != "" {
				a.add("config/paper-global.yml", problem, "proxies.velocity.secret 不可用于生产", true)
			}
			if mode, found := spaBool(flat, "proxies.velocity.online-mode"); found && mode {
				a.add("config/paper-global.yml", spaReasonProxyOff, "代理侧要求在线模式，与服务端配置不一致", false)
			}
		}
		if hasBungee && bungeeOn {
			a.add("config/paper-global.yml", spaReasonDualProxy, "启用 BungeeCord 转发", false)
			if !spigotLegacy {
				a.add("config/paper-global.yml", spaReasonNoPaper, "Paper 代理已启用但 spigot.yml 未声明 bungeecord", true)
			}
			if tokenMode, found := spaBool(flat, "proxies.bungee-cord.online-mode"); found && !tokenMode {
				a.add("config/paper-global.yml", spaReasonProxyOff, "bungee-cord.online-mode 已关闭", false)
			}
		}
		if !hasVelocity && !hasBungee && !onlineMode {
			a.add("server.properties", spaReasonOffline, "离线模式且未声明任何代理转发", true)
		}
	}

	if spigotLegacy {
		if strings.TrimSpace(spigotToken) == "" {
			a.add("spigot.yml", spaReasonNoToken, "bungeeguard-token 为空，legacy 转发可被伪造", true)
		} else if len(spigotToken) < spaMinSecretLength {
			a.add("spigot.yml", spaReasonTokenWeak, "bungeeguard-token 过短", true)
		}
	}

	if !onlineMode && !spigotLegacy && !paperLoaded {
		a.add("server.properties", spaReasonOffline, "离线模式缺少代理转发声明", true)
	}
	return a
}
