package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	sreMaxFindings = 16
	sreMaxFile     = 256 * 1024
	sreMiss        = "properties-missing"
	sreRead        = "properties-unreadable"
	sreLink        = "properties-symlink"
	sreEmpty       = "properties-empty"
	sreRconOn      = "rcon-enabled"
	sreRconPass    = "rcon-password-weak"
	sreRconDefault = "rcon-password-default"
	sreRconBroad   = "rcon-broadcast-to-ops"
	sreQueryOn     = "query-enabled"
	sreQueryPort   = "query-port-invalid"
	sreStatusOff   = "status-disabled"
)

type RconExposureFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type RconExposureAudit struct {
	ServerDir string
	Findings  []RconExposureFinding
}

func (a *RconExposureAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= sreMaxFindings {
		return
	}
	a.Findings = append(a.Findings, RconExposureFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *RconExposureAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *RconExposureAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *RconExposureAudit) Describe() string {
	return describeAuditFindings("RCON 与查询接口未暴露", a.Findings, 10,
		func(f RconExposureFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f RconExposureFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func sreReadProps(serverDir string, a *RconExposureAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(sreMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(sreRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(sreLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, sreMaxFile)
	if err != nil {
		a.add(sreRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(sreEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func sreBool(props map[string]string, key string) (bool, bool) {
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

func sreText(props map[string]string, key string) (string, bool) {
	raw, ok := props[key]
	if !ok {
		return "", false
	}
	return cfgStripQuotes(raw), true
}

func sreInt(props map[string]string, key string) (int, bool, bool) {
	raw, ok := props[key]
	if !ok {
		return 0, false, false
	}
	value, parsed := cfgParseInt(cfgStripQuotes(raw))
	if !parsed {
		return 0, true, false
	}
	return value, true, true
}

func AuditServerRconExposure(serverDir string) *RconExposureAudit {
	a := &RconExposureAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(sreMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := sreReadProps(serverDir, a)
	if !ok {
		return a
	}
	if value, has := sreBool(props, "enable-rcon"); has && value {
		a.add(sreRconOn, "enable-rcon=true 打开远程控制台", true)
		if pass, hasPass := sreText(props, "rcon.password"); hasPass {
			if pass == "" {
				a.add(sreRconPass, "rcon.password 为空", true)
			} else if len(pass) < 8 {
				a.add(sreRconPass, fmt.Sprintf("rcon.password 仅 %d 字符", len(pass)), false)
			}
			if strings.EqualFold(pass, "minecraft") || strings.EqualFold(pass, "password") {
				a.add(sreRconDefault, "rcon.password 使用默认值", true)
			}
		} else {
			a.add(sreRconPass, "缺少 rcon.password", true)
		}
	}
	if value, has := sreBool(props, "broadcast-rcon-to-ops"); has && value {
		a.add(sreRconBroad, "RCON 输出广播给全部管理员", false)
	}
	if value, has := sreBool(props, "enable-query"); has && value {
		a.add(sreQueryOn, "enable-query=true 暴露服务器信息", false)
	}
	if port, has, parsed := sreInt(props, "query-port"); has {
		if !parsed {
			a.add(sreQueryPort, "query-port 不是整数", true)
		} else if port < 1 || port > 65535 {
			a.add(sreQueryPort, fmt.Sprintf("query-port=%d 超出端口范围", port), true)
		}
	}
	if value, has := sreBool(props, "enable-status"); has && !value {
		a.add(sreStatusOff, "enable-status=false 关闭服务器列表状态", false)
	}
	return a
}
