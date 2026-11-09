package main

const (
	pklMaxFindings        = 48
	pklMaxYAML            = 512 * 1024
	pklMaxRate            = 600
	pklMaxAutoSave        = 24
	pklMaxKickMessage     = 256
	pklReasonOK           = "ok"
	pklReasonMissing      = "missing"
	pklReasonSymlink      = "symlink"
	pklReasonTooLarge     = "too-large"
	pklReasonUnreadable   = "unreadable"
	pklReasonBadConfig    = "bad-config"
	pklReasonBadValue     = "bad-value"
	pklReasonLimiterOff   = "limiter-disabled"
	pklReasonLimiterLoose = "limiter-loose"
	pklReasonKickMessage  = "bad-kick-message"
	pklReasonXrayOff      = "anti-xray-disabled"
	pklReasonXrayEngine   = "bad-engine-mode"
	pklReasonXrayEmpty    = "empty-block-list"
	pklReasonAutoSave     = "auto-save-burst"
)

type PacketLimiterFinding = auditFinding

type PacketLimiterAudit struct {
	ServerDir string
	Limits    int
	Findings  []PacketLimiterFinding
}

func (a *PacketLimiterAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pklMaxFindings, PacketLimiterFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PacketLimiterAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PacketLimiterFinding) bool { return f.Blocking })
}

func (a *PacketLimiterAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PacketLimiterFinding) bool { return f.Reason != pklReasonOK && !f.Blocking })
}
