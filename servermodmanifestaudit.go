package main

import (
	"fmt"
	"os"
	"path/filepath"
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

func AuditServerModManifest(modsDir string) (ModManifestAudit, error) {
	audit := ModManifestAudit{Dir: modsDir}
	if strings.TrimSpace(modsDir) == "" {
		return audit, nil
	}
	info, err := os.Lstat(modsDir)
	if os.IsNotExist(err) {
		return audit, nil
	}
	if err != nil {
		return audit, err
	}
	audit.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, ModManifestFinding{
			File: modsDir, Reason: modManifestReasonSymlink,
			Detail: "mods 目录本身是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.IsDir() {
		audit.Findings = append(audit.Findings, ModManifestFinding{
			File: modsDir, Reason: modManifestReasonNotRegular,
			Detail: "mods 路径不是目录", Blocking: true,
		})
		return audit, nil
	}

	entries, err := os.ReadDir(modsDir)
	if err != nil {
		return audit, err
	}
	modIDs := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !isManifestModJar(entry.Name()) {
			continue
		}
		if audit.Jars >= modManifestMaxJars {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: modsDir, Reason: modManifestReasonTooManyEntries,
				Detail: fmt.Sprintf("jar 数量超过 %d", modManifestMaxJars), Blocking: true,
			})
			break
		}
		audit.Jars++
		jarPath := filepath.Join(modsDir, entry.Name())
		jarInfo, statErr := os.Lstat(jarPath)
		if statErr != nil {
			return audit, statErr
		}
		if jarInfo.Mode()&os.ModeSymlink != 0 {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: entry.Name(), Reason: modManifestReasonSymlink,
				Detail: "jar 是符号链接，实际内容可被外部替换", Blocking: true,
			})
			continue
		}
		if !jarInfo.Mode().IsRegular() {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: entry.Name(), Reason: modManifestReasonNotRegular,
				Detail: "jar 不是普通文件", Blocking: true,
			})
			continue
		}
		if jarInfo.Size() > modManifestMaxJarBytes {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: entry.Name(), Reason: modManifestReasonTooLarge,
				Detail: fmt.Sprintf("jar 体积 %d 超过上限", jarInfo.Size()), Blocking: true,
			})
			continue
		}
		audit.scanJar(entry.Name(), jarPath, modIDs)
	}
	return audit, nil
}
