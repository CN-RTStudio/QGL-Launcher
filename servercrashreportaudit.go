package main

import "time"

const (
	crReasonOK            = "ok"
	crReasonMissing       = "missing"
	crReasonUnreadable    = "unreadable"
	crReasonSymlink       = "symlink"
	crReasonTooLarge      = "too-large"
	crReasonTooMany       = "too-many"
	crReasonBadName       = "bad-name"
	crReasonSecret        = "secret-leak"
	crReasonHomePath      = "home-path-leak"
	crReasonStale         = "stale-report"
	crReasonWorldWritable = "world-writable"

	crMaxFileBytes = 8 << 20
	crMaxFiles     = 128
	crMaxFindings  = 64
	crScanBytes    = 256 << 10
	crStaleAfter   = 30 * 24 * time.Hour
)

var crSecretPatterns = []string{
	"password=",
	"password:",
	"rcon.password",
	"rcon-password",
	"access_token",
	"authorization: bearer",
	"api_key",
	"apikey",
	"secret_key",
	"private_key",
	"-----begin",
	"sessionid=",
	"session_id=",
	"jdbc:mysql://",
	"mongodb://",
	"postgres://",
}
var crHomePatterns = []string{
	"/home/",
	"/root/",
	"c:\\users\\",
	"/users/",
}

type CrashReportFinding = auditFinding
type CrashReportAudit struct {
	Dir      string
	Files    []string
	Findings []CrashReportFinding
}
