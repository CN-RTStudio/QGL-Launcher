package main

import (
	"fmt"
	"strings"
)

const (
	playerDataReasonOK         = "ok"
	playerDataReasonSymlink    = "symlink"
	playerDataReasonNotRegular = "not-regular"
	playerDataReasonBadName    = "bad-name"
	playerDataReasonTooLarge   = "too-large"
	playerDataReasonTooMany    = "too-many"
	playerDataMaxFileBytes     = 128 << 20
	playerDataMaxFiles         = 50000
	playerDataMaxDirEntries    = 50000
)

var playerDataSubdirs = []string{"playerdata", "stats", "advancements"}

type PlayerDataFinding struct {
	Dir      string
	Name     string
	Reason   string
	Detail   string
	Blocking bool
}

type PlayerDataAudit struct {
	WorldDir string
	Present  bool
	Files    int
	Findings []PlayerDataFinding
}

func (a PlayerDataAudit) Blocking() bool {
	for _, finding := range a.Findings {
		if finding.Blocking {
			return true
		}
	}
	return false
}

func (a PlayerDataAudit) HasWarnings() bool {
	for _, finding := range a.Findings {
		if !finding.Blocking {
			return true
		}
	}
	return false
}

func (a PlayerDataAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("玩家数据目录共 %d 个文件，未发现异常", a.Files)
	}
	parts := make([]string, 0, len(a.Findings))
	for _, finding := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s/%s: %s", finding.Dir, finding.Name, finding.Detail))
	}
	return strings.Join(parts, "；")
}
