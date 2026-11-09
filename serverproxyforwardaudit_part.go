package main

import "strings"

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
