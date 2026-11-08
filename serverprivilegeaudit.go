package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	spvMaxFindings = 16
	spvMaxFile     = 256 * 1024
	spvMiss        = "properties-missing"
	spvRead        = "properties-unreadable"
	spvLink        = "properties-symlink"
	spvEmpty       = "properties-empty"
	spvOpLevel     = "op-permission-level-high"
	spvFuncLevel   = "function-permission-level-high"
	spvSecureChat  = "secure-profile-disabled"
	spvWhiteList   = "whitelist-disabled"
	spvEnforceList = "enforce-whitelist-off"
	spvLevelPath   = "level-name-traversal"
	spvLevelCtrl   = "level-name-control"
	spvPackScheme  = "resource-pack-insecure"
)

type PrivilegeScopeFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type PrivilegeScopeAudit struct {
	ServerDir string
	Findings  []PrivilegeScopeFinding
}

func (a *PrivilegeScopeAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= spvMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PrivilegeScopeFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PrivilegeScopeAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PrivilegeScopeAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PrivilegeScopeAudit) Describe() string {
	return describeAuditFindings("管理员权限与白名单策略处于安全区间", a.Findings, 10,
		func(f PrivilegeScopeFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f PrivilegeScopeFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func spvReadProps(serverDir string, a *PrivilegeScopeAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(spvMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(spvRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(spvLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, spvMaxFile)
	if err != nil {
		a.add(spvRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(spvEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func spvInt(props map[string]string, key string) (int, bool, bool) {
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

func spvBool(props map[string]string, key string) (bool, bool) {
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

func spvHasControl(text string) bool {
	for _, r := range text {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func AuditServerPrivilegeScope(serverDir string) *PrivilegeScopeAudit {
	a := &PrivilegeScopeAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(spvMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := spvReadProps(serverDir, a)
	if !ok {
		return a
	}
	if value, has, parsed := spvInt(props, "op-permission-level"); has {
		if !parsed {
			a.add(spvOpLevel, "op-permission-level 不是整数", true)
		} else if value > 2 {
			a.add(spvOpLevel, fmt.Sprintf("op-permission-level=%d 高于建议值 2", value), false)
		} else if value < 1 {
			a.add(spvOpLevel, fmt.Sprintf("op-permission-level=%d 低于 1", value), true)
		}
	}
	if value, has, parsed := spvInt(props, "function-permission-level"); has {
		if !parsed {
			a.add(spvFuncLevel, "function-permission-level 不是整数", true)
		} else if value > 2 {
			a.add(spvFuncLevel, fmt.Sprintf("function-permission-level=%d 高于建议值 2", value), false)
		}
	}
	if value, has := spvBool(props, "enforce-secure-profile"); has && !value {
		a.add(spvSecureChat, "enforce-secure-profile=false 允许未签名聊天", false)
	}
	if value, has := spvBool(props, "white-list"); has && !value {
		a.add(spvWhiteList, "white-list=false 未启用白名单", false)
	}
	if value, has := spvBool(props, "enforce-whitelist"); has && !value {
		a.add(spvEnforceList, "enforce-whitelist=false 白名单可被绕过", false)
	}
	if name, has := props["level-name"]; has {
		clean := cfgStripQuotes(strings.TrimSpace(name))
		if strings.Contains(clean, "..") || strings.Contains(clean, "\\") || strings.HasPrefix(clean, "/") {
			a.add(spvLevelPath, "level-name 含目录穿越片段", true)
		}
		if spvHasControl(clean) {
			a.add(spvLevelCtrl, "level-name 含控制字符", true)
		}
	}
	if pack, has := props["resource-pack"]; has {
		clean := cfgStripQuotes(strings.TrimSpace(pack))
		if clean != "" && !strings.HasPrefix(strings.ToLower(clean), "https://") {
			a.add(spvPackScheme, "resource-pack 未使用 HTTPS", true)
		}
	}
	return a
}
