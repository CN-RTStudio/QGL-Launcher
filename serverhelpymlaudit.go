package main

import (
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

type HelpYmlFinding = auditFinding

type HelpYmlAudit struct {
	ServerDir string
	Findings  []HelpYmlFinding
}

func (a *HelpYmlAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, shyMaxFindings, HelpYmlFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *HelpYmlAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f HelpYmlFinding) bool { return f.Blocking })
}

func (a *HelpYmlAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *HelpYmlAudit) Describe() string {
	return describeFileReasonDetail("服务器帮助配置未发现风险", a.Findings, 12)
}

func shyHasControlChars(text string) bool {
	return hasControlCharsText(text)
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
