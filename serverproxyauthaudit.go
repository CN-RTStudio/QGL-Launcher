package main

const (
	spaMaxFindings      = 40
	spaMaxProps         = 256 * 1024
	spaMaxYAML          = 512 * 1024
	spaMinSecretLength  = 12
	spaReasonOK         = "ok"
	spaReasonMissing    = "missing"
	spaReasonSymlink    = "symlink"
	spaReasonTooLarge   = "too-large"
	spaReasonUnreadable = "unreadable"
	spaReasonBadValue   = "bad-value"
	spaReasonOffline    = "offline-mode-with-proxy"
	spaReasonPreventOff = "proxy-connection-prevention-off"
	spaReasonLegacy     = "bungeecord-legacy-forwarding"
	spaReasonNoPaper    = "bungeecord-without-paper-proxy"
	spaReasonNoSecret   = "velocity-secret-missing"
	spaReasonWeak       = "velocity-secret-weak"
	spaReasonSecretBad  = "velocity-secret-invalid"
	spaReasonProxyOff   = "proxy-online-mode-off"
	spaReasonNoToken    = "bungeeguard-token-missing"
	spaReasonTokenWeak  = "bungeeguard-token-weak"
	spaReasonDualProxy  = "dual-proxy-enabled"
)

type ProxyAuthFinding = auditFinding
type ProxyAuthAudit struct {
	ServerDir string
	Findings  []ProxyAuthFinding
}

func (a *ProxyAuthAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spaMaxFindings, ProxyAuthFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *ProxyAuthAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ProxyAuthFinding) bool { return f.Blocking })
}

func (a *ProxyAuthAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
