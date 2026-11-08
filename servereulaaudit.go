package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	serMaxFindings = 24
	serMaxFile     = 64 * 1024
	serReasonMiss  = "missing"
	serReasonLink  = "symlink"
	serReasonLarge = "too-large"
	serReasonRead  = "unreadable"
	serReasonEmpty = "empty-file"
	serReasonDecl  = "eula-not-accepted"
	serReasonDup   = "duplicate-eula-key"
	serReasonConf  = "conflicting-eula-values"
	serReasonCtl   = "control-characters"
)

type EulaFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type EulaAudit struct {
	ServerDir string
	Findings  []EulaFinding
}

func (a *EulaAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= serMaxFindings {
		return
	}
	a.Findings = append(a.Findings, EulaFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *EulaAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *EulaAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *EulaAudit) Describe() string {
	return describeAuditFindings("EULA 协议文件未发现风险", a.Findings, 12,
		func(f EulaFinding) []string {
			return []string{f.File, f.Reason, f.Detail}
		},
		func(f EulaFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func serHasControlChars(text string) bool {
	for _, r := range text {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func serParseBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on":
		return true, true
	case "false", "no", "off":
		return false, true
	}
	return false, false
}

func AuditServerEula(serverDir string) *EulaAudit {
	a := &EulaAudit{ServerDir: serverDir}
	const rel = "eula.txt"
	if serverDir == "" {
		a.add(".", serReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", serReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, serReasonLink, "EULA 文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, serMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			a.add(rel, serReasonMiss, "尚未生成 EULA 协议文件", false)
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, serReasonLarge, fmt.Sprintf("EULA 文件超过 %d 字节", serMaxFile), true)
			return a
		}
		a.add(rel, serReasonRead, "EULA 文件不可读", false)
		return a
	}
	text := string(data)
	if strings.TrimSpace(text) == "" {
		a.add(rel, serReasonEmpty, "EULA 文件为空", false)
		return a
	}
	if serHasControlChars(text) {
		a.add(rel, serReasonCtl, "EULA 文件含控制字符", true)
	}
	assignments := 0
	accepted := false
	decimal := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed[:eq], "\ufeff")))
		if key != "eula" {
			continue
		}
		assignments++
		value := cfgStripInlineComment(strings.TrimSpace(trimmed[eq+1:]))
		value = cfgStripQuotes(strings.TrimSpace(value))
		parsed, known := serParseBool(value)
		if !known {
			a.add(rel, serReasonConf, "eula 取值无法识别: "+value, true)
			continue
		}
		if parsed {
			accepted = true
		} else {
			decimal = true
		}
	}
	if assignments == 0 {
		a.add(rel, serReasonDecl, "EULA 文件未声明 eula 字段", false)
		return a
	}
	if assignments > 1 {
		a.add(rel, serReasonDup, fmt.Sprintf("eula 字段重复声明 %d 次", assignments), false)
		if accepted && decimal {
			a.add(rel, serReasonConf, "eula 同时出现接受与拒绝两种取值", true)
		}
	}
	if !accepted {
		a.add(rel, serReasonDecl, "EULA 尚未接受，服务端会拒绝启动", false)
	}
	return a
}
