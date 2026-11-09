package main

const (
	syrMaxFile      = 256 * 1024
	syrMaxFindings  = 18
	syrDefaultPort  = 25575
	syrMinPassword  = 12
	syrRCONEnabled  = "rcon-enabled"
	syrRCONEmpty    = "rcon-password-empty"
	syrRCONWeak     = "rcon-password-weak"
	syrRCONDefault  = "rcon-password-default"
	syrRCONPortBad  = "rcon-port-invalid"
	syrRCONPortCol  = "rcon-port-collision"
	syrBroadcast    = "rcon-broadcast-enabled"
	syrQueryEnabled = "query-enabled"
	syrQueryPortCol = "query-port-collision"
	syrMissing      = "properties-missing"
	syrUnreadable   = "properties-unreadable"
	syrWeakChars    = "rcon-password-low-variety"
)

type RconHardeningFinding struct {
	Reason   string
	Detail   string
	Blocking bool
}
type RconHardeningAudit struct {
	ServerDir string
	Findings  []RconHardeningFinding
}

func (a *RconHardeningAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, syrMaxFindings, RconHardeningFinding{Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *RconHardeningAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f RconHardeningFinding) bool { return f.Blocking })
}
func (a *RconHardeningAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
