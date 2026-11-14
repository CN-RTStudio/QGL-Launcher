package main

import ()

const (
	baselineReasonCreated    = "created"
	baselineReasonModified   = "modified"
	baselineReasonRemoved    = "removed"
	baselineReasonAdded      = "added"
	baselineReasonCorrupt    = "corrupt"
	baselineReasonUnreadable = "unreadable"

	baselineVersion  = 1
	baselineMaxBytes = 4 << 20
)

var baselineFileNames = []string{
	"server.properties",
	"ops.json",
	"whitelist.json",
	"banned-players.json",
	"banned-ips.json",
	"eula.txt",
}

type BaselineFinding = auditFinding

type BaselineAudit struct {
	Path     string
	Created  bool
	Hashes   map[string]string
	Findings []BaselineFinding
}
type baselineStore struct {
	Version   int               `json:"version"`
	ServerDir string            `json:"serverDir"`
	Files     map[string]string `json:"files"`
}

func (a *BaselineAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f BaselineFinding) bool { return f.Blocking })
}
func (a *BaselineAudit) HasWarnings() bool {
	return a != nil && len(a.Findings) > 0
}
