package main

import (
	"strings"
)

const (
	saxMaxFindings      = 40
	saxMaxYAML          = 512 * 1024
	saxMaxHiddenBlocks  = 64
	saxMaxRadius        = 4
	saxMinBlockHeight   = 16
	saxMaxBlockHeight   = 384
	saxReasonOK         = "ok"
	saxReasonMissing    = "missing"
	saxReasonSymlink    = "symlink"
	saxReasonTooLarge   = "too-large"
	saxReasonUnreadable = "unreadable"
	saxReasonDisabled   = "anti-xray-disabled"
	saxReasonModeWeak   = "engine-mode-weak"
	saxReasonModeBad    = "engine-mode-invalid"
	saxReasonHiddenNone = "hidden-blocks-empty"
	saxReasonHiddenMany = "hidden-blocks-too-many"
	saxReasonReplace    = "replacement-blocks-empty"
	saxReasonRadius     = "update-radius-out-of-range"
	saxReasonHeight     = "max-block-height-out-of-range"
	saxReasonLava       = "lava-obscuring-disabled"
	saxReasonListBad    = "list-entry-invalid"
)

type AntiXrayFinding = auditFinding

type AntiXrayAudit struct {
	ServerDir string
	Findings  []AntiXrayFinding
}

func (a *AntiXrayAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, saxMaxFindings, AntiXrayFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *AntiXrayAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f AntiXrayFinding) bool { return f.Blocking })
}

func (a *AntiXrayAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *AntiXrayAudit) Describe() string {
	return describeFileReason("反矿透配置未发现风险", a.Findings, 12)
}

func saxLoadText(a *AntiXrayAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func saxIndent(line string) int {
	count := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

func saxListItems(text, key string) []string {
	lines := strings.Split(text, "\n")
	items := []string{}
	found := -1
	baseIndent := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if found < 0 {
			colon := strings.Index(trimmed, ":")
			if colon < 0 {
				continue
			}
			name := strings.TrimSpace(trimmed[:colon])
			if name != key {
				continue
			}
			rest := strings.TrimSpace(trimmed[colon+1:])
			if rest != "" && rest != "[]" {
				continue
			}
			found = i
			baseIndent = saxIndent(line)
			continue
		}
		if saxIndent(line) <= baseIndent {
			break
		}
		if !strings.HasPrefix(trimmed, "- ") {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		items = append(items, cfgStripQuotes(item))
		if len(items) > 256 {
			break
		}
	}
	return items
}
