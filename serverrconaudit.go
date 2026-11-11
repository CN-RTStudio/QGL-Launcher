package main

import ()

const (
	rconReasonOK             = "ok"
	rconReasonMissing        = "missing"
	rconReasonSymlink        = "symlink"
	rconReasonUnreadable     = "unreadable"
	rconReasonEmptyPassword  = "empty-rcon-password"
	rconReasonWeakPassword   = "weak-rcon-password"
	rconReasonBadPassword    = "bad-rcon-password"
	rconReasonBadPort        = "bad-rcon-port"
	rconReasonPortCollision  = "rcon-port-collision"
	rconReasonBroadcast      = "rcon-broadcast-to-ops"
	rconReasonQueryEnabled   = "query-enabled"
	rconReasonQueryPublic    = "query-public"
	rconReasonQueryPort      = "bad-query-port"
	rconReasonQueryCollision = "query-port-collision"
	rconReasonStalePassword  = "stale-rcon-password"
	rconReasonDuplicateKey   = "duplicate-key"
	rconMinPasswordRunes     = 8
	rconMaxPasswordRunes     = 256
)

type RconFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerRconAudit struct {
	Path     string
	Present  bool
	Findings []RconFinding
}

func (a *ServerRconAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f RconFinding) bool { return f.Blocking })
}
func (a *ServerRconAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != rconReasonOK {
			return true
		}
	}
	return false
}
func (a *ServerRconAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f RconFinding) string { return f.Reason })
}
