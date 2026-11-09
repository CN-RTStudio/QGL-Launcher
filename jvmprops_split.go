package main

import (
	"strings"
)

// propValueLoadsRemoteOrFile 判定属性值是否指向“远程 URL / file: 外部位置”。
// 仅用于那些“本地路径合法、但外部位置危险”的属性（如 log4j.configurationFile）。
func propValueLoadsRemoteOrFile(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return true
	}
	if strings.HasPrefix(v, "file:") {
		return true
	}
	// 双等号整体覆盖写法（java.security.properties 用）在属性名侧已被精确拦截，
	// 这里不做泛化。
	return false
}

// jvmSystemPropertyThreat 按（已小写的）属性名 / 值判定危险并返回原因码。
// 普通属性返回空原因。value 是否危险仅对个别“仅外部位置才危险”的属性有意义。
func jvmSystemPropertyThreat(name, value string) (reason string, dangerous bool) {
	if name == "" {
		return "", false
	}
	if r, ok := jvmExactPropThreats[name]; ok {
		// log4j 配置文件只拦远程 / file: 位置；普通本地路径放行。
		if r == "log4j-factory" {
			// configurationFactory 是类名，无论值是什么都危险（精确表里其余
			// log4j 项才是工厂），configurationFile 走前缀单独判定。
			return r, true
		}
		return r, true
	}
	for _, p := range jvmPrefixPropThreats {
		if name == p.name || strings.HasPrefix(name, p.name+".") {
			return p.reason, true
		}
	}
	// log4j（1.x/2.x）配置文件：本地文件系统路径是启动器常见用法，保留；
	// 一旦指向 http(s):// 或 file: 即判危险，防止远程配置 / SSRF 类加载。
	if (name == "log4j.configurationfile" || name == "log4j2.configurationfile") &&
		propValueLoadsRemoteOrFile(value) {
		return "log4j-config", true
	}
	return "", false
}

// jvmPropArgThreat 是 parse + 判定的热路径封装，供 jvmArgThreat 直接调用。
func jvmPropArgThreat(lower string) (dangerous bool) {
	name, value, isProp := parseSystemPropertyArg(lower)
	if !isProp {
		return false
	}
	_, bad := jvmSystemPropertyThreat(name, value)
	return bad
}
