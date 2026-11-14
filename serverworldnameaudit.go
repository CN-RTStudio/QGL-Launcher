package main

import ()

const (
	swnMaxFindings     = 32
	swnMaxProps        = 256 * 1024
	swnReasonMissing   = "missing"
	swnReasonSymlink   = "symlink"
	swnReasonTooLarge  = "too-large"
	swnReasonUnread    = "unreadable"
	swnReasonName      = "level-name-invalid"
	swnReasonDirLink   = "world-dir-symlink"
	swnReasonLevelType = "level-type-unknown"
	swnReasonGenerator = "generator-settings-present"
	swnReasonNoProps   = "properties-missing"
)

var swnKnownLevelTypes = map[string]bool{
	"default":              true,
	"flat":                 true,
	"large_biomes":         true,
	"amplified":            true,
	"single_biome_surface": true,
	"normal":               true,
	"customized":           true,
}

type WorldNameFinding = auditFinding
type WorldNameAudit struct {
	ServerDir string
	Findings  []WorldNameFinding
}

func (a *WorldNameAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, swnMaxFindings, WorldNameFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WorldNameAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WorldNameFinding) bool { return f.Blocking })
}
