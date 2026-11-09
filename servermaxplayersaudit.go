package main

const (
	smpMaxFindings = 14
	smpReasonCount = "max-players-invalid"
	smpReasonMany  = "max-players-too-high"
	smpReasonIdle  = "idle-timeout-disabled"
	smpReasonRate  = "rate-limit-disabled"
	smpReasonView  = "view-distance-out-of-range"
	smpReasonSim   = "simulation-distance-out-of-range"
)

type MaxPlayersFinding struct {
	Reason   string
	Detail   string
	Blocking bool
}

type MaxPlayersAudit struct {
	ServerDir string
	Findings  []MaxPlayersFinding
}

func (a *MaxPlayersAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, smpMaxFindings, MaxPlayersFinding{Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *MaxPlayersAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f MaxPlayersFinding) bool { return f.Blocking })
}

func (a *MaxPlayersAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *MaxPlayersAudit) Describe() string {
	return describeAuditFindings("容量与限流配置未发现风险", a.Findings, 10,
		func(f MaxPlayersFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f MaxPlayersFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}
