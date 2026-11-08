package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	spdMaxFindings       = 36
	spdMaxConfig         = 256 * 1024
	spdMaxProps          = 256 * 1024
	spdPrivilegedPortMax = 1024
	spdReasonOK          = "ok"
	spdReasonMissing     = "missing"
	spdReasonSymlink     = "symlink"
	spdReasonTooLarge    = "too-large"
	spdReasonUnreadable  = "unreadable"
	spdReasonPort        = "webserver-port-invalid"
	spdReasonPortPriv    = "webserver-port-privileged"
	spdReasonPortClash   = "webserver-port-conflict"
	spdReasonBindAll     = "webserver-bind-all"
	spdReasonSymlinks    = "webserver-allow-symlinks"
	spdReasonCORS        = "cors-wildcard"
	spdReasonCDN         = "cdn-insecure"
	spdReasonTilePath    = "tilespath-invalid"
	spdReasonBadValue    = "bad-value"
)

type DynmapFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type DynmapAudit struct {
	ServerDir string
	Findings  []DynmapFinding
}

func (a *DynmapAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= spdMaxFindings {
		return
	}
	a.Findings = append(a.Findings, DynmapFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *DynmapAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f DynmapFinding) bool { return f.Blocking })
}

func (a *DynmapAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *DynmapAudit) Describe() string {
	return describeAuditFindings("网页地图配置未发现风险", a.Findings, 12,
		func(f DynmapFinding) []string {
			return []string{f.File, f.Reason}
		},
		func(f DynmapFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func spdLoadText(a *DynmapAudit, root, rel string, maxBytes int64) (string, bool) {
	path := filepath.Join(root, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, spdReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return "", false
	}
	data, err := readBoundedFile(path, maxBytes)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return "", false
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, spdReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", maxBytes), true)
			return "", false
		}
		a.add(rel, spdReasonUnreadable, "配置文件不可读", false)
		return "", false
	}
	return string(data), true
}

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
