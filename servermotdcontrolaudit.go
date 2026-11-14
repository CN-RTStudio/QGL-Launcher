package main

const (
	smcMaxFindings  = 14
	smcMaxFile      = 256 * 1024
	smcMaxRunes     = 256
	smcMaxSection   = 32
	smcMiss         = "motd-missing"
	smcRead         = "motd-unreadable"
	smcLink         = "properties-symlink"
	smcEmpty        = "motd-empty"
	smcControl      = "motd-control-character"
	smcNewline      = "motd-line-break"
	smcBidi         = "motd-bidi-override"
	smcZeroWidth    = "motd-zero-width"
	smcTooLong      = "motd-too-long"
	smcSection      = "motd-section-code-invalid"
	smcSectionDense = "motd-section-code-dense"
	smcMalformed    = "properties-line-malformed"
	smcKeySpace     = "properties-key-whitespace"
)

type MotdControlFinding = auditFinding
type MotdControlAudit struct {
	ServerDir string
	Findings  []MotdControlFinding
}

func (a *MotdControlAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, smcMaxFindings, MotdControlFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *MotdControlAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f MotdControlFinding) bool { return f.Blocking })
}
func (a *MotdControlAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
