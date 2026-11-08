package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	sbmMaxFindings     = 36
	sbmMaxConfig       = 256 * 1024
	sbmMaxProps        = 256 * 1024
	sbmPrivilegedPort  = 1024
	sbmReasonOK        = "ok"
	sbmReasonMissing   = "missing"
	sbmReasonSymlink   = "symlink"
	sbmReasonTooLarge  = "too-large"
	sbmReasonUnread    = "unreadable"
	sbmReasonPort      = "webserver-port-invalid"
	sbmReasonPrivPort  = "webserver-port-privileged"
	sbmReasonPortClash = "webserver-port-conflict"
	sbmReasonBindAll   = "webserver-bind-all"
	sbmReasonDownload  = "accept-download-enabled"
	sbmReasonDataPath  = "data-path-escape"
	sbmReasonMetrics   = "metrics-enabled"
	sbmReasonRate      = "rate-limit-disabled"
	sbmReasonBadValue  = "bad-value"
)

type BlueMapFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type BlueMapAudit struct {
	ServerDir string
	Findings  []BlueMapFinding
}

func (a *BlueMapAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= sbmMaxFindings {
		return
	}
	a.Findings = append(a.Findings, BlueMapFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BlueMapAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *BlueMapAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *BlueMapAudit) Describe() string {
	return describeAuditFindings("BlueMap 网页地图配置未发现风险", a.Findings, 12,
		func(f BlueMapFinding) []string {
			return []string{f.File, f.Reason}
		},
		func(f BlueMapFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func sbmLoadText(a *BlueMapAudit, root, rel string, maxBytes int64) (string, bool) {
	path := filepath.Join(root, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, sbmReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return "", false
	}
	data, err := readBoundedFile(path, maxBytes)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return "", false
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, sbmReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", maxBytes), true)
			return "", false
		}
		a.add(rel, sbmReasonUnread, "配置文件不可读", false)
		return "", false
	}
	return string(data), true
}

func sbmParseConf(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if trimmed == "{" || trimmed == "}" || strings.HasSuffix(trimmed, "{") {
			continue
		}
		sep := strings.IndexAny(trimmed, ":=")
		if sep <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:sep]))
		if dot := strings.LastIndex(key, "."); dot >= 0 {
			key = key[dot+1:]
		}
		if space := strings.LastIndex(key, " "); space >= 0 {
			key = key[space+1:]
		}
		value := strings.TrimSpace(trimmed[sep+1:])
		value = strings.TrimSuffix(value, ",")
		value = cfgStripQuotes(value)
		out[key] = value
	}
	return out
}

func sbmBool(props map[string]string, key string) (bool, bool) {
	value, ok := props[strings.ToLower(key)]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	default:
		return false, false
	}
}

func AuditServerBlueMap(serverDir string) *BlueMapAudit {
	a := &BlueMapAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", sbmReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sbmReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", sbmReasonMissing, "服务器目录不存在", false)
		return a
	}

	serverPort := 25565
	if text, ok := sbmLoadText(a, serverDir, "server.properties", sbmMaxProps); ok {
		props := pxParseProperties(text)
		if raw, found := props["server-port"]; found {
			if value, parsed := cfgParseInt(strings.TrimSpace(raw)); parsed && value > 0 && value <= 65535 {
				serverPort = value
			}
		}
	}

	webRel := "plugins/BlueMap/webserver.conf"
	webText, webOK := sbmLoadText(a, serverDir, webRel, sbmMaxConfig)
	if webOK {
		props := sbmParseConf(webText)
		if enabled, found := sbmBool(props, "enabled"); found && !enabled {
			webOK = false
		}
		if webOK {
			if raw, found := props["port"]; found {
				trimmed := strings.TrimSpace(raw)
				if port, parsed := cfgParseInt(trimmed); !parsed || port <= 0 || port > 65535 {
					a.add(webRel, sbmReasonPort, "webserver 端口非法", true)
				} else {
					if port < sbmPrivilegedPort {
						a.add(webRel, sbmReasonPrivPort, "监听特权端口需要额外权限", true)
					}
					if port == serverPort {
						a.add(webRel, sbmReasonPortClash, "网页端口与游戏端口冲突", true)
					}
				}
			}
			if ip, found := props["ip"]; found {
				trimmed := strings.TrimSpace(ip)
				if trimmed == "" || trimmed == "0.0.0.0" || trimmed == "::" || trimmed == "[::]" {
					a.add(webRel, sbmReasonBindAll, "绑定全部网卡，未限制来源", false)
				}
			}
			if raw, found := props["max-connection-per-second"]; found {
				if value, parsed := cfgParseInt(strings.TrimSpace(raw)); parsed && value <= 0 {
					a.add(webRel, sbmReasonRate, "每秒连接上限被关闭，易被压垮", true)
				}
			}
		}
	}

	coreRel := "plugins/BlueMap/core.conf"
	coreText, coreOK := sbmLoadText(a, serverDir, coreRel, sbmMaxConfig)
	if coreOK {
		props := sbmParseConf(coreText)
		if value, found := sbmBool(props, "accept-download"); found && value {
			a.add(coreRel, sbmReasonDownload, "允许客户端批量下载地图数据", false)
		}
		if value, found := sbmBool(props, "metrics"); found && value {
			a.add(coreRel, sbmReasonMetrics, "向外部端点上报统计数据", false)
		}
		if data, found := props["data"]; found {
			trimmed := strings.TrimSpace(data)
			if trimmed == "" {
				a.add(coreRel, sbmReasonDataPath, "数据目录为空", true)
			} else if filepath.IsAbs(trimmed) || strings.Contains(trimmed, "..") || strings.ContainsAny(trimmed, "\\") {
				a.add(coreRel, sbmReasonDataPath, "数据目录含绝对路径或越界片段", true)
			}
		}
	}

	if !webOK && !coreOK {
		a.add("plugins/BlueMap", sbmReasonMissing, "未找到 BlueMap 配置", false)
	}
	return a
}
