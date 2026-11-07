package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	sfaMaxFindings = 16
	sfaMaxFile     = 256 * 1024
	sfaMiss        = "properties-missing"
	sfaRead        = "properties-unreadable"
	sfaLink        = "properties-symlink"
	sfaEmpty       = "properties-empty"
	sfaOpLevel     = "op-permission-level-invalid"
	sfaOpLevelMax  = "op-permission-level-maximum"
	sfaFuncLevel   = "function-permission-level-low"
	sfaCommandBlk  = "command-block-enabled"
	sfaConsoleOPS  = "broadcast-console-to-ops-on"
	sfaRconOPS     = "broadcast-rcon-to-ops-on"
	sfaAdminLog    = "log-admin-commands-off"
	sfaFeedback    = "send-command-feedback-on"
)

type AdminFeedbackFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type AdminFeedbackAudit struct {
	ServerDir string
	Findings  []AdminFeedbackFinding
}

func (a *AdminFeedbackAudit) add(reason, detail string, blocking bool) {
	if len(a.Findings) >= sfaMaxFindings {
		return
	}
	a.Findings = append(a.Findings, AdminFeedbackFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *AdminFeedbackAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *AdminFeedbackAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *AdminFeedbackAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "管理员反馈与权限档位未发现风险配置"
	}
	sorted := make([]AdminFeedbackFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Detail < sorted[j].Detail
	})
	var b strings.Builder
	for i, f := range sorted {
		if i >= 10 {
			b.WriteString(fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(f.Reason)
		if f.Detail != "" {
			b.WriteString("(")
			b.WriteString(f.Detail)
			b.WriteString(")")
		}
	}
	return b.String()
}

func sfaReadProps(serverDir string, a *AdminFeedbackAudit) (map[string]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(sfaMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(sfaRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(sfaLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, sfaMaxFile)
	if err != nil {
		a.add(sfaRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	props := pxParseProperties(text)
	if len(props) == 0 {
		a.add(sfaEmpty, "属性文件无可解析键值", false)
		return nil, false
	}
	return props, true
}

func sfaBool(props map[string]string, key string) (bool, bool) {
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

func sfaInt(props map[string]string, key string) (int, bool, bool) {
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

func AuditServerAdminFeedback(serverDir string) *AdminFeedbackAudit {
	a := &AdminFeedbackAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(sfaMiss, "未配置服务器目录", false)
		return a
	}
	props, ok := sfaReadProps(serverDir, a)
	if !ok {
		return a
	}
	if level, has, parsed := sfaInt(props, "op-permission-level"); has {
		if !parsed {
			a.add(sfaOpLevel, "op-permission-level 不是整数", true)
		} else if level < 1 || level > 4 {
			a.add(sfaOpLevel, fmt.Sprintf("op-permission-level=%d 超出 1..4", level), true)
		} else if level == 4 {
			a.add(sfaOpLevelMax, "op-permission-level=4 允许管理员绕过全部限制", false)
		}
	}
	if level, has, parsed := sfaInt(props, "function-permission-level"); has {
		if !parsed {
			a.add(sfaFuncLevel, "function-permission-level 不是整数", true)
		} else if level < 2 {
			a.add(sfaFuncLevel, fmt.Sprintf("function-permission-level=%d 过低，普通玩家可执行函数", level), true)
		}
	}
	if enabled, has := sfaBool(props, "enable-command-block"); has && enabled {
		a.add(sfaCommandBlk, "已启用命令方块，可被用于非授权命令执行", true)
	}
	if enabled, has := sfaBool(props, "broadcast-console-to-ops"); has && enabled {
		a.add(sfaConsoleOPS, "控制台全部输出广播给所有 OP，易泄漏敏感信息", false)
	}
	if enabled, has := sfaBool(props, "broadcast-rcon-to-ops"); has && enabled {
		a.add(sfaRconOPS, "RCON 会话内容广播给所有 OP，易泄漏远端管理凭据", false)
	}
	if enabled, has := sfaBool(props, "log-admin-commands"); has && !enabled {
		a.add(sfaAdminLog, "关闭管理员命令日志，事后无法追责", false)
	}
	if enabled, has := sfaBool(props, "send-command-feedback"); has && enabled {
		a.add(sfaFeedback, "命令执行反馈对所有玩家可见，泄露管理操作", false)
	}
	return a
}
