package main

import (
	"fmt"
	"strings"
)

const (
	pfwMaxFindings            = 48
	pfwMaxProps               = 256 * 1024
	pfwMaxYAML                = 512 * 1024
	pfwMinSecretLen           = 32
	pfwReasonOK               = "ok"
	pfwReasonMissing          = "missing"
	pfwReasonSymlink          = "symlink"
	pfwReasonTooLarge         = "too-large"
	pfwReasonBadValue         = "bad-value"
	pfwReasonOffline          = "offline-mode"
	pfwReasonOfflineExposed   = "offline-mode-exposed"
	pfwReasonWeakSecret       = "weak-proxy-secret"
	pfwReasonLegacyBungee     = "legacy-bungee-forwarding"
	pfwReasonConflict         = "conflicting-proxy-mode"
	pfwReasonUncheckedForward = "unchecked-forwarding"
	pfwReasonProxyOnline      = "proxy-offline-mode"
	pfwReasonUnreadable       = "unreadable"
	pfwReasonBadConfig        = "bad-config"
)

type ProxyForwardFinding = auditFinding
type ProxyForwardAudit struct {
	ServerDir string
	ProxyKind string
	Findings  []ProxyForwardFinding
}

func (a *ProxyForwardAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pfwMaxFindings, ProxyForwardFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *ProxyForwardAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ProxyForwardFinding) bool { return f.Blocking })
}
func (a *ProxyForwardAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ProxyForwardFinding) bool { return f.Reason != pfwReasonOK && !f.Blocking })
}
func (a *ProxyForwardAudit) Describe() string {
	return describeFindings(a.Findings, func(f ProxyForwardFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}
func pfwLoadText(a *ProxyForwardAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func pfwPropBool(props map[string]string, key string) (bool, bool) {
	value, ok := props[key]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	return false, false
}
