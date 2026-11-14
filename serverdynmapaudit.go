package main

import ()

const (
	spdMaxFindings       = 36
	spdMaxConfig         = 256 * 1024
	spdMaxProps          = 256 * 1024
	spdPrivilegedPortMax = 1024
	spdReasonOK          = "ok"
	spdReasonMissing     = "missing"
	spdReasonSymlink     = "symlink"
	spdReasonTooLarge    = "too-large"
	spdReasonUnreadable  = "unreadable"
	spdReasonPort        = "webserver-port-invalid"
	spdReasonPortPriv    = "webserver-port-privileged"
	spdReasonPortClash   = "webserver-port-conflict"
	spdReasonBindAll     = "webserver-bind-all"
	spdReasonSymlinks    = "webserver-allow-symlinks"
	spdReasonCORS        = "cors-wildcard"
	spdReasonCDN         = "cdn-insecure"
	spdReasonTilePath    = "tilespath-invalid"
	spdReasonBadValue    = "bad-value"
)

type DynmapFinding = auditFinding
type DynmapAudit struct {
	ServerDir string
	Findings  []DynmapFinding
}

func (a *DynmapAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spdMaxFindings, DynmapFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *DynmapAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f DynmapFinding) bool { return f.Blocking })
}
