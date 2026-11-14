package main

import (
	"os"
	"strings"
)

func spdBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}

func spdPortConflict(serverPort, webPort int) bool {
	return serverPort > 0 && serverPort == webPort
}

func AuditServerDynmap(serverDir string) *DynmapAudit {
	a := &DynmapAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", spdReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", spdReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", spdReasonMissing, "服务器目录不存在", false)
		return a
	}

	serverPort := 25565
	if text, ok := spdLoadText(a, serverDir, "server.properties", spdMaxProps); ok {
		props := pxParseProperties(text)
		if raw, found := props["server-port"]; found {
			if value, parsed := cfgParseInt(strings.TrimSpace(raw)); parsed && value > 0 && value <= 65535 {
				serverPort = value
			}
		}
	}

	text, ok := spdLoadText(a, serverDir, "plugins/dynmap/configuration.txt", spdMaxConfig)
	if !ok {
		return a
	}
	props := cfgFlattenYAML(text)
	if len(props) == 0 {
		a.add("plugins/dynmap/configuration.txt", spdReasonBadValue, "配置为空或格式不可识别", false)
		return a
	}

	if disabled, found := spdBool(props, "disable-webserver"); found && disabled {
		return a
	}

	if raw, found := props["webserver-port"]; found {
		trimmed := strings.TrimSpace(raw)
		if port, parsed := cfgParseInt(trimmed); !parsed || port <= 0 || port > 65535 {
			a.add("plugins/dynmap/configuration.txt", spdReasonPort, "webserver-port 非法", true)
		} else {
			if port < spdPrivilegedPortMax {
				a.add("plugins/dynmap/configuration.txt", spdReasonPortPriv, "监听特权端口需要额外权限", true)
			}
			if spdPortConflict(serverPort, port) {
				a.add("plugins/dynmap/configuration.txt", spdReasonPortClash, "监听端口与游戏端口冲突", true)
			}
		}
	}

	if bind, found := props["webserver-bindaddress"]; found {
		trimmed := strings.TrimSpace(bind)
		if trimmed == "" || trimmed == "0.0.0.0" || trimmed == "::" || trimmed == "[::]" {
			a.add("plugins/dynmap/configuration.txt", spdReasonBindAll, "绑定全部网卡，未限制来源", false)
		}
	}

	if value, found := spdBool(props, "webserver-allow-symlinks"); found && value {
		a.add("plugins/dynmap/configuration.txt", spdReasonSymlinks, "允许符号链接，网页目录可越界读取", true)
	}

	if origin, found := props["cors-allow-origin"]; found {
		if strings.TrimSpace(origin) == "*" {
			a.add("plugins/dynmap/configuration.txt", spdReasonCORS, "CORS 允许任意来源", true)
		}
	}

	if cdn, found := spdBool(props, "use-cdn"); found && cdn {
		if url, has := props["cdn-url"]; has && strings.HasPrefix(strings.ToLower(strings.TrimSpace(url)), "http://") {
			a.add("plugins/dynmap/configuration.txt", spdReasonCDN, "CDN 使用明文 HTTP", true)
		}
	}

	if tiles, found := props["tilespath"]; found {
		trimmed := strings.TrimSpace(tiles)
		if trimmed == "" {
			a.add("plugins/dynmap/configuration.txt", spdReasonTilePath, "tilespath 为空", true)
		} else if strings.HasPrefix(trimmed, "/") || strings.Contains(trimmed, "..") || strings.ContainsAny(trimmed, "\\:") {
			a.add("plugins/dynmap/configuration.txt", spdReasonTilePath, "tilespath 含绝对路径或穿越片段", true)
		}
	}
	return a
}
