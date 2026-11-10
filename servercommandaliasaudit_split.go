package main

import (
	"regexp"
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
	return describeTaggedFindings("服务器命令别名未发现异常", a.Findings, caReasonOK, "", caMaxFindings,
		func(f CommandAliasFinding) string { return f.Reason },
		func(f CommandAliasFinding) string { return f.File },
		func(f CommandAliasFinding) string { return f.Detail })
}

func (a *CommandAliasAudit) add(file, alias, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, caMaxFindings, CommandAliasFinding{File: file, Alias: alias, Reason: reason, Detail: detail, Blocking: blocking})
}
