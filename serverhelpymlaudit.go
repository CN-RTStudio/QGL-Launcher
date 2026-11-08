package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	shyMaxFindings = 32
	shyMaxFile     = 256 * 1024
	shyMaxTopics   = 128
	shyMaxLine     = 256
	shyReasonMiss  = "missing"
	shyReasonLink  = "symlink"
	shyReasonLarge = "too-large"
	shyReasonRead  = "unreadable"
	shyReasonEmpty = "empty-config"
	shyReasonTag   = "unsafe-yaml-tag"
	shyReasonCtl   = "control-characters"
	shyReasonTopic = "too-many-topics"
	shyReasonLong  = "overlong-topic"
	shyReasonObfus = "obfuscated-formatting"
)

type HelpYmlFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type HelpYmlAudit struct {
	ServerDir string
	Findings  []HelpYmlFinding
}

func (a *HelpYmlAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= shyMaxFindings {
		return
	}
	a.Findings = append(a.Findings, HelpYmlFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *HelpYmlAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *HelpYmlAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *HelpYmlAudit) Describe() string {
	return describeAuditFindings("服务器帮助配置未发现风险", a.Findings, 12,
		func(f HelpYmlFinding) []string {
			return []string{f.File, f.Reason, f.Detail}
		},
		func(f HelpYmlFinding) string {
			if f.Detail == "" {
				return f.File + ": " + f.Reason
			}
			return f.File + ": " + f.Reason + "(" + f.Detail + ")"
		})
}

func shyHasControlChars(text string) bool {
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

func shyFindUnsafeTag(text string) string {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "!!") {
			return strings.TrimSpace(strings.SplitN(trimmed, " ", 2)[0])
		}
		if idx := strings.Index(trimmed, "!!"); idx >= 0 {
			token := trimmed[idx:]
			if len(token) > 3 {
				return strings.TrimSpace(strings.SplitN(token, " ", 2)[0])
			}
		}
		if strings.HasPrefix(trimmed, "!<") {
			return "!<"
		}
	}
	return ""
}

func shyCountTopics(text string) int {
	count := 0
	inTopics := false
	for _, line := range strings.Split(text, "\n") {
		raw := strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 {
			inTopics = strings.HasPrefix(trimmed, "general-topics:") || strings.HasPrefix(trimmed, "index-topics:")
			continue
		}
		if !inTopics {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			count++
		}
	}
	return count
}

func AuditServerHelpYml(serverDir string) *HelpYmlAudit {
	a := &HelpYmlAudit{ServerDir: serverDir}
	const rel = "help.yml"
	if serverDir == "" {
		a.add(".", shyReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", shyReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, shyReasonLink, "帮助配置为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, shyMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, shyReasonLarge, fmt.Sprintf("帮助配置超过 %d 字节", shyMaxFile), true)
			return a
		}
		a.add(rel, shyReasonRead, "帮助配置不可读", false)
		return a
	}
	text := string(data)
	if strings.TrimSpace(text) == "" {
		a.add(rel, shyReasonEmpty, "帮助配置为空", false)
		return a
	}
	if tag := shyFindUnsafeTag(text); tag != "" {
		a.add(rel, shyReasonTag, "含可被反序列化的 YAML 标签 "+tag, true)
	}
	if shyHasControlChars(text) {
		a.add(rel, shyReasonCtl, "帮助配置含控制字符", true)
	}
	topics := shyCountTopics(text)
	if topics > shyMaxTopics {
		a.add(rel, shyReasonTopic, fmt.Sprintf("帮助条目 %d 超过 %d", topics, shyMaxTopics), false)
	}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > shyMaxLine {
			a.add(rel, shyReasonLong, "存在超长帮助文本行", false)
			break
		}
	}
	if strings.Contains(text, "&k") || strings.Contains(text, "\u00a7k") {
		a.add(rel, shyReasonObfus, "帮助文本使用混淆格式码", false)
	}
	return a
}
