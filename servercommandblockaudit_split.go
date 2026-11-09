package main

import (
	"fmt"
	"strings"
)

func (a *CommandBlockAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, scbMaxFindings, CommandBlockFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *CommandBlockAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CommandBlockFinding) bool { return f.Blocking })
}

func (a *CommandBlockAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f CommandBlockFinding) bool { return f.Reason != scbReasonOK && !f.Blocking })
}

func (a *CommandBlockAudit) Describe() string {
	return describeFindings(a.Findings, func(f CommandBlockFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func scbLoadText(a *CommandBlockAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func scbPropBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}

func scbPropInt(props map[string]string, key string) (int, bool) {
	value, ok := props[strings.ToLower(key)]
	if !ok {
		return 0, false
	}
	return cfgParseInt(value)
}
