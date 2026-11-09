package main

import (
	"fmt"
	"strings"
)

const (
	modManifestReasonOK              = "ok"
	modManifestReasonSymlink         = "symlink"
	modManifestReasonNotRegular      = "not-regular"
	modManifestReasonTooLarge        = "too-large"
	modManifestReasonBadZip          = "bad-zip"
	modManifestReasonTooManyEntries  = "too-many-entries"
	modManifestReasonEntryTooLarge   = "entry-too-large"
	modManifestReasonBombRatio       = "bomb-ratio"
	modManifestReasonSuspiciousEntry = "suspicious-entry"
	modManifestReasonDuplicateEntry  = "duplicate-entry"
	modManifestReasonBadMetadata     = "bad-metadata"
	modManifestReasonDuplicateID     = "duplicate-mod-id"
	modManifestReasonEmptyArchive    = "empty-archive"
	modManifestMaxJars               = 2000
	modManifestMaxJarBytes           = int64(512) << 20
	modManifestMaxEntries            = 20000
	modManifestMaxEntryBytes         = uint64(256) << 20
	modManifestMaxRatio              = 200
	modManifestMaxMetadataBytes      = int64(512) << 10
)

type ModManifestFinding struct {
	File     string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type ModManifestAudit struct {
	Dir      string
	Present  bool
	Jars     int
	Entries  int
	Findings []ModManifestFinding
}

func (audit ModManifestAudit) Blocking() bool {
	return anyBlocking(audit.Findings, func(f ModManifestFinding) bool { return f.Blocking })
}

func (audit ModManifestAudit) HasWarnings() bool {
	return len(audit.Findings) > 0 && !audit.Blocking()
}

func (audit ModManifestAudit) Codes() []string {
	return findingCodes(audit.Findings, func(f ModManifestFinding) string { return f.Reason })
}

func (audit ModManifestAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "模组清单校验通过"
	}
	parts := make([]string, 0, len(audit.Findings))
	for _, finding := range audit.Findings {
		entry := finding.Entry
		if entry == "" {
			entry = finding.File
		}
		parts = append(parts, fmt.Sprintf("%s:%s(%s)", finding.File, entry, finding.Detail))
	}
	return strings.Join(parts, "；")
}

func isManifestModJar(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".jar") && !strings.HasSuffix(lower, ".jar.disabled")
}
