package main

import (
	"archive/zip"
	"fmt"
	"strings"
)

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

func (audit DatapackAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "数据包目录未发现风险项"
	}
	var parts []string
	for _, finding := range audit.Findings {
		parts = append(parts, fmt.Sprintf("%s: %s", finding.Name, finding.Detail))
	}
	return strings.Join(parts, "；")
}

func scanDatapackZip(path string) (string, string, bool) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return datapackReasonBadZip, "ZIP 结构无法解析", true
	}
	defer reader.Close()
	if len(reader.File) > datapackMaxEntries {
		return datapackReasonTooLarge, fmt.Sprintf("条目数超过 %d", datapackMaxEntries), true
	}
	for _, entry := range reader.File {
		if suspiciousServerJarEntry(entry.Name) {
			return datapackReasonBadEntry, "含越界条目名 " + entry.Name, true
		}
	}
	return datapackReasonOK, "", false
}
