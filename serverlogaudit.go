package main

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
