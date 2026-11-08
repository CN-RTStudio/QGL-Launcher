package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

const (
	hoReasonOK            = "ok"
	hoReasonMissing       = "missing"
	hoReasonUnreadable    = "unreadable"
	hoReasonSymlink       = "symlink"
	hoReasonTooLarge      = "too-large"
	hoReasonWorldWritable = "world-writable"
	hoReasonWorldReadable = "world-readable"
	hoReasonTooManyTopics = "too-many-topics"
	hoReasonTextTooLong   = "text-too-long"
	hoReasonControlChars  = "control-chars"
	hoReasonRemoteURL     = "remote-url"
	hoReasonWildcardPerm  = "wildcard-permission"
	hoReasonShadowTopic   = "shadowed-topic"
	hoReasonEmptyTopic    = "empty-topic"
	hoReasonDuplicateKey  = "duplicate-key"
	hoReasonUnknownField  = "unknown-field"
	hoReasonBadSection    = "bad-section"

	hoMaxFileBytes = 1 << 20
	hoMaxTopics    = 64
	hoMaxShortText = 256
	hoMaxFullText  = 4096
	hoMaxFindings  = 48
)

var hoConfigCandidates = []string{
	"help.yml",
	"config/help.yml",
}

var hoBuiltinTopics = []string{
	"help",
	"version",
	"plugins",
	"reload",
	"timings",
	"spark",
	"op",
	"deop",
}

var hoKnownSections = []string{
	"general-topics",
	"index-topics",
}

var hoKnownFields = []string{
	"shorttext",
	"fulltext",
	"permission",
}

type HelpOverrideFinding struct {
	File     string
	Topic    string
	Reason   string
	Detail   string
	Blocking bool
}

type HelpOverrideAudit struct {
	Dir      string
	Findings []HelpOverrideFinding
	Topics   int
}

func (a HelpOverrideAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a HelpOverrideAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != hoReasonOK {
			return true
		}
	}
	return false
}

func (a HelpOverrideAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == hoReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail))
		if len(parts) >= hoMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器帮助覆盖未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *HelpOverrideAudit) add(file, topic, reason, detail string, blocking bool) {
	if len(a.Findings) >= hoMaxFindings {
		return
	}
	a.Findings = append(a.Findings, HelpOverrideFinding{
		File:     file,
		Topic:    topic,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}

func hoCheckFile(audit *HelpOverrideAudit, rel string) bool {
	path := filepath.Join(audit.Dir, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.add(rel, "", hoReasonMissing, "帮助配置不存在", false)
		} else {
			audit.add(rel, "", hoReasonUnreadable, err.Error(), false)
		}
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(rel, "", hoReasonSymlink, "帮助配置是符号链接", true)
		return false
	}
	if !info.Mode().IsRegular() {
		audit.add(rel, "", hoReasonUnreadable, "帮助配置不是普通文件", true)
		return false
	}
	if info.Size() > hoMaxFileBytes {
		audit.add(rel, "", hoReasonTooLarge, fmt.Sprintf("帮助配置 %d 字节", info.Size()), true)
		return false
	}
	if info.Mode().Perm()&0o022 != 0 {
		audit.add(rel, "", hoReasonWorldWritable, fmt.Sprintf("权限 %#o 允许他人写入", info.Mode().Perm()), true)
	}
	if info.Mode().Perm()&0o004 != 0 {
		audit.add(rel, "", hoReasonWorldReadable, fmt.Sprintf("权限 %#o 允许他人读取", info.Mode().Perm()), false)
	}
	return true
}

func hoIndentOf(line string) int {
	width := 0
	for width < len(line) && line[width] == ' ' {
		width++
	}
	return width
}

func hoHasControlRune(text string) bool {
	for _, r := range text {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func hoHasRemoteURL(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "http://") || strings.Contains(lower, "https://")
}

func hoStripInlineComment(text string) string {
	lower := strings.ToLower(text)
	for _, marker := range []string{" #", "\t#"} {
		if idx := strings.Index(lower, marker); idx >= 0 {
			return text[:idx]
		}
	}
	return text
}

func hoTopicName(raw string) string {
	name := strings.TrimSpace(raw)
	name = strings.TrimSuffix(name, ":")
	return strings.Trim(name, `"'`)
}

func hoAuditTopic(audit *HelpOverrideAudit, rel, name, body string) {
	audit.Topics++
	clean := strings.ToLower(strings.TrimSpace(name))
	if clean == "" {
		audit.add(rel, name, hoReasonEmptyTopic, "帮助主题名为空", false)
		return
	}
	for _, builtin := range hoBuiltinTopics {
		if clean == builtin {
			audit.add(rel, name, hoReasonShadowTopic, "覆盖内置帮助主题 "+builtin, false)
			return
		}
	}
	if len(body) > hoMaxFullText {
		audit.add(rel, name, hoReasonTextTooLong, fmt.Sprintf("主题文本 %d 字符", len(body)), true)
	}
	if hoHasControlRune(body) {
		audit.add(rel, name, hoReasonControlChars, "主题文本含控制字符", true)
	}
	if hoHasRemoteURL(body) {
		audit.add(rel, name, hoReasonRemoteURL, "主题文本含外部链接", false)
	}
	if strings.Contains(body, "\u00a7") {
		audit.add(rel, name, hoReasonUnknownField, "主题文本含格式化转义", false)
	}
}

func hoScanHelp(audit *HelpOverrideAudit, rel, content string) {
	section := ""
	sectionIndent := -1
	topic := ""
	topicIndent := -1
	var topicBody strings.Builder
	permission := ""
	flush := func() {
		if topic != "" {
			hoAuditTopic(audit, rel, topic, topicBody.String())
			if permission != "" {
				for _, token := range strings.Split(permission, ",") {
					trimmed := strings.Trim(strings.TrimSpace(token), `"'`)
					if trimmed == "*" || strings.HasSuffix(trimmed, ".*") || trimmed == "bukkit.*" {
						audit.add(rel, topic, hoReasonWildcardPerm, "权限通配 "+trimmed, false)
					}
				}
			}
		}
		topic = ""
		topicBody.Reset()
		permission = ""
	}
	blockScalar := false
	blockIndent := -1
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, "\r")
		stripped := strings.TrimSpace(hoStripInlineComment(line))
		if stripped == "" {
			continue
		}
		indent := hoIndentOf(line)
		if blockScalar {
			if indent > blockIndent {
				topicBody.WriteString(strings.TrimSpace(line))
				topicBody.WriteString("\n")
				continue
			}
			blockScalar = false
		}
		if indent == 0 {
			flush()
			key := strings.ToLower(strings.TrimSuffix(strings.SplitN(stripped, ":", 2)[0], " "))
			known := false
			for _, candidate := range hoKnownSections {
				if key == candidate {
					known = true
					break
				}
			}
			if !known && key != "" {
				audit.add(rel, "", hoReasonBadSection, "未知顶层段落 "+key, false)
			}
			section = key
			sectionIndent = 0
			continue
		}
		if section == "" {
			audit.add(rel, "", hoReasonBadSection, "缩进内容缺少顶层段落", false)
			continue
		}
		if topic == "" || (sectionIndent >= 0 && indent == sectionIndent+2 && !strings.HasPrefix(stripped, "-")) {
			flush()
			topic = hoTopicName(stripped)
			topicIndent = indent
			if idx := strings.Index(stripped, ":"); idx >= 0 {
				live := strings.TrimSpace(stripped[idx+1:])
				if live != "" && live != "|-" && live != "|" && live != ">" {
					topicBody.WriteString(live)
				} else if strings.HasPrefix(live, "|") || strings.HasPrefix(live, ">") {
					blockScalar = true
					blockIndent = indent
				}
			}
			continue
		}
		if topic != "" && indent > topicIndent {
			key, value := stripped, ""
			if idx := strings.Index(stripped, ":"); idx >= 0 {
				key = strings.ToLower(strings.TrimSpace(stripped[:idx]))
				value = strings.TrimSpace(stripped[idx+1:])
			}
			knownField := false
			for _, field := range hoKnownFields {
				if key == field {
					knownField = true
					break
				}
			}
			if !knownField {
				audit.add(rel, topic, hoReasonUnknownField, "未知字段 "+key, false)
				continue
			}
			switch key {
			case "shorttext":
				if len(value) > hoMaxShortText {
					audit.add(rel, topic, hoReasonTextTooLong, fmt.Sprintf("短文本 %d 字符", len(value)), false)
				}
				topicBody.WriteString(value)
			case "fulltext":
				if strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") {
					blockScalar = true
					blockIndent = indent
					continue
				}
				topicBody.WriteString(value)
			case "permission":
				permission = value
			}
			continue
		}
		if topic != "" {
			audit.add(rel, topic, hoReasonDuplicateKey, "主题字段层级异常", false)
		}
	}
	flush()
	if audit.Topics > hoMaxTopics {
		audit.add(rel, "", hoReasonTooManyTopics, fmt.Sprintf("帮助主题总数 %d", audit.Topics), true)
	}
}

func AuditServerHelpOverride(serverDir string) HelpOverrideAudit {
	audit := HelpOverrideAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("server", "", hoReasonMissing, "服务器目录不可用", false)
		return audit
	}
	for _, rel := range hoConfigCandidates {
		if !hoCheckFile(&audit, rel) {
			continue
		}
		data, readErr := readBoundedFile(filepath.Join(serverDir, filepath.FromSlash(rel)), hoMaxFileBytes)
		if readErr != nil {
			audit.add(rel, "", hoReasonUnreadable, readErr.Error(), false)
			continue
		}
		hoScanHelp(&audit, rel, string(data))
	}
	if audit.Topics == 0 {
		audit.add("help.yml", "", hoReasonOK, "未声明帮助覆盖", false)
	}
	return audit
}
