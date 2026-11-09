package main

const (
	syqMaxFindings  = 16
	syqMaxFile      = 256 * 1024
	syqMissing      = "properties-missing"
	syqLevelEscape  = "level-name-path-escape"
	syqLevelAbsent  = "level-name-empty"
	syqMotdControl  = "motd-control-characters"
	syqMotdLength   = "motd-too-long"
	syqMotdLink     = "motd-contains-url"
	syqIPWildcard   = "server-ip-wildcard"
	syqIPInvalid    = "server-ip-invalid"
	syqIPPublic     = "server-ip-public"
	syqPortInvalid  = "server-port-invalid"
	syqPortLow      = "server-port-privileged"
	syqMaxPlayers   = "max-players-nonpositive"
	syqViewDistance = "view-distance-too-large"
	syqNetCompress  = "network-compression-threshold-negative"
	syqAllowFlight  = "allow-flight-enabled"
)

type QueryExposureFinding struct {
	Reason   string
	Detail   string
	Blocking bool
}

type QueryExposureAudit struct {
	ServerDir string
	Findings  []QueryExposureFinding
}

func (a *QueryExposureAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, syqMaxFindings, QueryExposureFinding{Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *QueryExposureAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f QueryExposureFinding) bool { return f.Blocking })
}

func (a *QueryExposureAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *QueryExposureAudit) Describe() string {
	return describeAuditFindings("对外暴露相关配置未发现风险", a.Findings, 9,
		func(f QueryExposureFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f QueryExposureFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func syqHasControl(text string) bool {
	for _, r := range text {
		if r < 0x20 && r != '\t' {
			return true
		}
		if r == 0x7f {
			return true
		}
		if r >= 0x80 && r <= 0x9f {
			return true
		}
	}
	return false
}
