package main

import (
	"fmt"
	"sort"
	"strings"
)

func (a AccessControlAudit) Describe() string {
	var parts []string
	for _, f := range a.Findings {
		if f.Reason == acReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "server"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= acMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "访问控制未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *AccessControlAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, acMaxFindings, AccessControlFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

type opEntry struct {
	UUID              string `json:"uuid"`
	Name              string `json:"name"`
	Level             int    `json:"level"`
	BypassesPlayerCap bool   `json:"bypassesPlayerLimit"`
}

type whitelistEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type bannedEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Created string `json:"created"`
}
