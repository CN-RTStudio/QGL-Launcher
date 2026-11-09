package main

import "regexp"

const (
	regionReasonOK          = "ok"
	regionReasonSymlink     = "symlink"
	regionReasonNotRegular  = "not-regular"
	regionReasonTooLarge    = "too-large"
	regionReasonShortHeader = "short-header"
	regionReasonBadOffset   = "bad-offset"
	regionReasonOutOfRange  = "out-of-range"
	regionReasonBadLength   = "bad-length"
	regionReasonBadName     = "bad-name"
	regionReasonTooMany     = "too-many-files"
	regionHeaderBytes       = 8192
	regionSectorBytes       = 4096
	regionSlotCount         = 1024
	regionMaxFiles          = 1024
	regionMaxBytes          = int64(2) << 30
)

var regionNamePattern = regexp.MustCompile(`^r\.-?[0-9]+\.-?[0-9]+\.mca$`)

type RegionFinding struct {
	Region   string
	Chunk    int
	Reason   string
	Detail   string
	Blocking bool
}
type RegionAudit struct {
	WorldDir    string
	RegionDirs  int
	RegionFiles int
	Chunks      int
	Findings    []RegionFinding
}
