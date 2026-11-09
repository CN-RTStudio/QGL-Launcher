package main

import (
	"fmt"
	"strings"
)

const (
	sqbMaxFindings    = 40
	sqbMaxProps       = 256 * 1024
	sqbMaxBukkit      = 512 * 1024
	sqbReasonOK       = "ok"
	sqbReasonMissing  = "missing"
	sqbReasonSymlink  = "symlink"
	sqbReasonTooLarge = "too-large"
	sqbReasonUnread   = "unreadable"
	sqbReasonBadValue = "bad-value"
	sqbReasonQueryOn  = "query-enabled"
	sqbReasonBindAll  = "query-bind-all"
	sqbReasonPortLow  = "query-port-privileged"
	sqbReasonPortZero = "query-port-zero"
	sqbReasonOrphan   = "query-port-orphaned"
	sqbReasonHostPath = "server-ip-not-address"
	sqbReasonStatus   = "status-disabled"
	sqbReasonCollide  = "query-rcon-port-collision"
)

type QueryBindingFinding = auditFinding

type QueryBindingAudit struct {
	ServerDir string
	Findings  []QueryBindingFinding
}

func (a *QueryBindingAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sqbMaxFindings, QueryBindingFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *QueryBindingAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f QueryBindingFinding) bool { return f.Blocking })
}

func (a *QueryBindingAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f QueryBindingFinding) bool { return f.Reason != sqbReasonOK && !f.Blocking })
}

func (a *QueryBindingAudit) Describe() string {
	return describeFindings(a.Findings, func(f QueryBindingFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func sqbLoadText(a *QueryBindingAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func sqbBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}

func sqbPort(props map[string]string, key string) (int, bool, bool) {
	return propsLookupInt(props, key)
}

func sqbIsWildcardHost(host string) bool {
	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0", "::", "[::]", "*":
		return true
	}
	return false
}

func sqbHostLooksInvalid(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.ContainsAny(host, "/\\") || strings.Contains(host, "://") {
		return true
	}
	if strings.ContainsAny(host, " \t") {
		return true
	}
	if strings.Contains(host, "@") || strings.Contains(host, "?") || strings.Contains(host, "#") {
		return true
	}
	return false
}
