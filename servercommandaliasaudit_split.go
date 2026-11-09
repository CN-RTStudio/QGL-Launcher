package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var caAliasNamePattern = regexp.MustCompile(`^/?[A-Za-z0-9_.:-]{1,48}$`)

type CommandAliasFinding struct {
	File     string
	Alias    string
	Reason   string
	Detail   string
	Blocking bool
}

type CommandAliasAudit struct {
	Dir      string
	Findings []CommandAliasFinding
	Aliases  int
}

func (a CommandAliasAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CommandAliasFinding) bool { return f.Blocking })
}

func (a CommandAliasAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f CommandAliasFinding) bool { return !f.Blocking && f.Reason != caReasonOK })
}

func (a CommandAliasAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == caReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail))
		if len(parts) >= caMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器命令别名未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *CommandAliasAudit) add(file, alias, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, caMaxFindings, CommandAliasFinding{File: file, Alias: alias, Reason: reason, Detail: detail, Blocking: blocking})
}
