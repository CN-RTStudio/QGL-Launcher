package main

const (
	sicMaxFile      = 256 * 1024
	sicMaxSide      = 1024
	sicExpectedSide = 64
	sicMaxFindings  = 24
	sicReasonMiss   = "missing"
	sicReasonLink   = "symlink"
	sicReasonLarge  = "too-large"
	sicReasonRead   = "unreadable"
	sicReasonMagic  = "not-png"
	sicReasonShape  = "invalid-ihdr"
	sicReasonSide   = "oversized-icon"
	sicReasonSize   = "non-standard-size"
)

type IconFileFinding = auditFinding

type IconFileAudit struct {
	ServerDir string
	Findings  []IconFileFinding
}

func (a *IconFileAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sicMaxFindings, IconFileFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *IconFileAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f IconFileFinding) bool { return f.Blocking })
}

func (a *IconFileAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *IconFileAudit) Describe() string {
	return describeFileReasonDetail("服务器图标未发现风险", a.Findings, 12)
}
