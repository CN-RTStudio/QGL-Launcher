package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	snmMaxFindings = 18
	snmMaxFile     = 256 * 1024
	snmMiss        = "properties-missing"
	snmRead        = "properties-unreadable"
	snmOffline     = "online-mode-off"
	snmSecureOff   = "secure-profile-off"
	snmProxyOpen   = "proxy-connections-allowed"
	snmCompressOff = "compression-threshold-disabled"
	snmCompressLow = "compression-threshold-too-low"
	snmEmpty       = "properties-empty"
	snmLink        = "properties-symlink"
	snmBom         = "properties-bom"
)

type OnlineModeFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type OnlineModeAudit struct {
	ServerDir string
	Findings  []OnlineModeFinding
}

func (a *OnlineModeAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= snmMaxFindings {
		return
	}
	a.Findings = append(a.Findings, OnlineModeFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *OnlineModeAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *OnlineModeAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *OnlineModeAudit) Describe() string {
	return describeAuditFindings("在线认证配置未发现风险", a.Findings, 12,
		func(f OnlineModeFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f OnlineModeFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func snmReadProps(serverDir string, a *OnlineModeAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(snmMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(snmRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(snmLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, snmMaxFile)
	if err != nil {
		a.add(snmRead, err.Error(), true)
		return nil, false
	}
	text := string(data)
	if strings.HasPrefix(text, "\ufeff") {
		a.add(snmBom, "属性文件带 BOM 头，首键可能失效", false)
		text = strings.TrimPrefix(text, "\ufeff")
	}
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(snmEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func snmBool(props map[string]string, key string) (bool, bool) {
	raw, ok := props[key]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "on", "yes":
		return true, true
	case "false", "off", "no":
		return false, true
	}
	return false, false
}

func AuditServerOnlineMode(serverDir string) *OnlineModeAudit {
	a := &OnlineModeAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(snmMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := snmReadProps(serverDir, a)
	if !ok {
		return a
	}
	if online, has := snmBool(props, "online-mode"); has && !online {
		a.add(snmOffline, "离线模式允许任意伪造用户名与 UUID", true)
	}
	if secure, has := snmBool(props, "enforce-secure-profile"); has && !secure {
		a.add(snmSecureOff, "关闭聊天签名校验，可被重放冒充", false)
	}
	if proxy, has := snmBool(props, "prevent-proxy-connections"); has && !proxy {
		if online, has2 := snmBool(props, "online-mode"); has2 && online {
			a.add(snmProxyOpen, "在线模式却允许代理转发连接", false)
		}
	}
	raw, has := props["network-compression-threshold"]
	if has {
		value, parsed := cfgParseInt(raw)
		if parsed {
			if value < 0 {
				a.add(snmCompressOff, "关闭网络压缩，放大带宽消耗", false)
			} else if value >= 0 && value < 64 {
				a.add(snmCompressLow, fmt.Sprintf("压缩阈值 %d 过低，易被压缩炸弹拖垮", value), false)
			}
		} else {
			a.add(snmCompressLow, "压缩阈值不是整数: "+cfgStripQuotes(raw), false)
		}
	}
	return a
}
