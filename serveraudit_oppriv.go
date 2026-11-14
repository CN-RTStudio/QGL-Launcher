package main

import ()

const (
	operatorReasonOK         = "ok"
	operatorReasonTooLarge   = "too-large"
	operatorReasonSymlink    = "symlink"
	operatorReasonNotRegular = "not-regular"
	operatorReasonUnreadable = "unreadable"
	operatorReasonBadJSON    = "bad-json"
	operatorReasonDuplicate  = "duplicate"
	operatorReasonBadUUID    = "bad-uuid"
	operatorReasonBadName    = "bad-name"
	operatorReasonBadLevel   = "bad-level"

	operatorMaxBytes = 1 << 20
)

var operatorFileNames = []string{"ops.json", "whitelist.json", "banned-players.json"}

type OperatorFinding struct {
	File     string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}
type ServerOperatorAudit struct {
	Files    map[string]int
	Findings []OperatorFinding
}
type operatorEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               int    `json:"level"`
	BypassesPlayerLimit bool   `json:"bypassesPlayerLimit"`
}

func (a *ServerOperatorAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f OperatorFinding) bool { return f.Blocking })
}

func (a *ServerOperatorAudit) HasWarnings() bool {
	return a != nil && len(a.Findings) > 0
}
