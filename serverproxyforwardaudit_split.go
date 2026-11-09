package main

import (
	"fmt"
	"strings"
)

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
