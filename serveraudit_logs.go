package main

import ()

const (
	logAuditReasonSymlink       = "symlink"
	logAuditReasonNotRegular    = "not-regular"
	logAuditReasonTooLarge      = "too-large"
	logAuditReasonBadName       = "bad-name"
	logAuditReasonTooMany       = "too-many"
	logAuditReasonUnreadable    = "unreadable"
	logAuditReasonWorldWritable = "world-writable"
	logAuditReasonExploitMark   = "exploit-attempt"
	logAuditReasonScanTooLarge  = "scan-too-large"

	serverLogMaxEntries   = 512
	serverLogMaxRotated   = 64
	serverLogMaxFileBytes = 32 << 20
	serverLogScanBytes    = 8 << 20
	serverLogMaxNameRunes = 128
)

var logExploitMarkers = []string{
	"${jndi:",
	"ldap://",
	"ldaps://",
	"rmi://",
	"dns://",
	"${lower:",
	"${upper:",
	"${env:",
}

type LogFinding struct {
	Name     string
	Reason   string
	Detail   string
	Blocking bool
}
type ServerLogAudit struct {
	Dir      string
	Present  bool
	Entries  int
	Findings []LogFinding
}

func (a *ServerLogAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f LogFinding) bool { return f.Blocking })
}
