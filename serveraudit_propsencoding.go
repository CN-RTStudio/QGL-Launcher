package main

import ()

const (
	setbMaxFindings = 24
	setbMaxFile     = 512 * 1024
	setbMaxLine     = 512
	setbReasonMiss  = "missing"
	setbReasonLink  = "symlink"
	setbReasonLarge = "too-large"
	setbReasonRead  = "unreadable"
	setbReasonBOM   = "utf8-bom"
	setbReasonUTF8  = "invalid-utf8"
	setbReasonCRLF  = "crlf-endings"
	setbReasonNUL   = "nul-byte"
	setbReasonDup   = "duplicate-key"
	setbReasonKey   = "invalid-key"
	setbReasonLong  = "long-line"
	setbReasonEsc   = "bad-escape"
)

type PropertiesEncodingFinding = auditFinding
type PropertiesEncodingAudit struct {
	ServerDir string
	Findings  []PropertiesEncodingFinding
}

func (a *PropertiesEncodingAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, setbMaxFindings, PropertiesEncodingFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PropertiesEncodingAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropertiesEncodingFinding) bool { return f.Blocking })
}
