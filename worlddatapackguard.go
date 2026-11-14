package main

import ()

const (
	datapackReasonOK       = "ok"
	datapackReasonSymlink  = "symlink"
	datapackReasonBadEntry = "bad-entry"
	datapackReasonTooLarge = "too-large"
	datapackReasonBadZip   = "bad-zip"
	datapackMaxPacks       = 512
	datapackMaxBytes       = int64(64) << 20
	datapackMaxEntries     = 10000
)

type DatapackFinding struct {
	Name     string
	Reason   string
	Detail   string
	Blocking bool
}
type DatapackAudit struct {
	Dir      string
	Present  bool
	Packs    int
	Findings []DatapackFinding
}

func (audit DatapackAudit) Blocking() bool {
	return anyBlocking(audit.Findings, func(f DatapackFinding) bool { return f.Blocking })
}
