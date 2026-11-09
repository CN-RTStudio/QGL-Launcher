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
