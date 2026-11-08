package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	caReasonOK             = "ok"
	caReasonMissing        = "missing"
	caReasonUnreadable     = "unreadable"
	caReasonSymlink        = "symlink"
	caReasonTooLarge       = "too-large"
	caReasonWorldWritable  = "world-writable"
	caReasonWorldReadable  = "world-readable"
	caReasonCatchAll       = "catch-all-alias"
	caReasonShadowed       = "shadowed-command"
	caReasonInternalTarget = "internal-target"
	caReasonTooManyAlias   = "too-many-aliases"
	caReasonBadName        = "bad-alias-name"
	caReasonDuplicate      = "duplicate-alias"
	caReasonVariableTarget = "variable-target"
	caReasonEmptyTarget    = "empty-target"
	caReasonBadIndent      = "bad-indent"
	caReasonUnknownSection = "unknown-section"

	caMaxFileBytes = 1 << 20
	caMaxAliases   = 64
	caMaxTargets   = 8
	caMaxFindings  = 48
)

var caConfigCandidates = []string{
	"commands.yml",
	"config/commands.yml",
}

var caPrivilegedCommands = []string{
	"op",
	"deop",
	"stop",
	"restart",
	"ban",
	"ban-ip",
	"pardon",
	"pardon-ip",
	"whitelist",
	"kick",
	"save-off",
	"save-all",
	"reload",
	"plugins",
	"permissions",
}

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
	if len(a.Findings) >= caMaxFindings {
		return
	}
	a.Findings = append(a.Findings, CommandAliasFinding{
		File:     file,
		Alias:    alias,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}
