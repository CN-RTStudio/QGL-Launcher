package main

import (
	"fmt"
	"sort"
	"strings"
)

type ppOpEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               int    `json:"level"`
	BypassesPlayerLimit bool   `json:"bypassesPlayerLimit"`
}

type PlayerPrivacyFinding struct {
	Source   string
	Reason   string
	Detail   string
	Blocking bool
}

type PlayerPrivacyAudit struct {
	Dir      string
	Files    []string
	Findings []PlayerPrivacyFinding
}

func (a PlayerPrivacyAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PlayerPrivacyFinding) bool { return f.Blocking })
}

func (a PlayerPrivacyAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PlayerPrivacyFinding) bool { return !f.Blocking && f.Reason != ppReasonOK })
}

func (a PlayerPrivacyAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == ppReasonOK {
			continue
		}
		label := f.Source
		if label == "" {
			label = "player-data"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= ppMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "玩家身份数据未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *PlayerPrivacyAudit) add(source, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, ppMaxFindings, PlayerPrivacyFinding{Source: source, Reason: reason, Detail: detail, Blocking: blocking})
}
