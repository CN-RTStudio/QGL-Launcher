package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

func AuditWorldPlayerData(worldDir string) (PlayerDataAudit, error) {
	audit := PlayerDataAudit{WorldDir: worldDir}
	for _, name := range playerDataSubdirs {
		dir := filepath.Join(worldDir, name)
		info, err := os.Lstat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return audit, err
		}
		audit.Present = true
		if info.Mode()&os.ModeSymlink != 0 {
			audit.Findings = append(audit.Findings, PlayerDataFinding{
				Dir: name, Name: name, Reason: playerDataReasonSymlink, Detail: "目录是符号链接", Blocking: true,
			})
			continue
		}
		if !info.IsDir() {
			audit.Findings = append(audit.Findings, PlayerDataFinding{
				Dir: name, Name: name, Reason: playerDataReasonNotRegular, Detail: "路径不是目录", Blocking: true,
			})
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return audit, err
		}
		if len(entries) > playerDataMaxDirEntries {
			audit.Findings = append(audit.Findings, PlayerDataFinding{
				Dir: name, Name: name, Reason: playerDataReasonTooMany,
				Detail: fmt.Sprintf("目录条目 %d 超过上限 %d", len(entries), playerDataMaxDirEntries), Blocking: true,
			})
		}
		for _, entry := range entries {
			entryName := entry.Name()
			path := filepath.Join(dir, entryName)
			entryInfo, statErr := os.Lstat(path)
			if statErr != nil {
				return audit, statErr
			}
			if entryInfo.Mode()&os.ModeSymlink != 0 {
				audit.Findings = append(audit.Findings, PlayerDataFinding{
					Dir: name, Name: entryName, Reason: playerDataReasonSymlink, Detail: "条目是符号链接", Blocking: true,
				})
				continue
			}
			if entry.IsDir() {
				audit.Findings = append(audit.Findings, PlayerDataFinding{
					Dir: name, Name: entryName, Reason: playerDataReasonNotRegular, Detail: "条目不是普通文件", Blocking: true,
				})
				continue
			}
			if !entryInfo.Mode().IsRegular() {
				audit.Findings = append(audit.Findings, PlayerDataFinding{
					Dir: name, Name: entryName, Reason: playerDataReasonNotRegular, Detail: "条目不是普通文件", Blocking: true,
				})
				continue
			}
			audit.Files++
			if audit.Files > playerDataMaxFiles {
				audit.Findings = append(audit.Findings, PlayerDataFinding{
					Dir: name, Name: entryName, Reason: playerDataReasonTooMany,
					Detail: fmt.Sprintf("文件数超过上限 %d", playerDataMaxFiles), Blocking: true,
				})
				continue
			}
			if !validPlayerDataName(name, entryName) {
				audit.Findings = append(audit.Findings, PlayerDataFinding{
					Dir: name, Name: entryName, Reason: playerDataReasonBadName, Detail: "文件名不符合 UUID 规则", Blocking: false,
				})
			}
			if entryInfo.Size() > playerDataMaxFileBytes {
				audit.Findings = append(audit.Findings, PlayerDataFinding{
					Dir: name, Name: entryName, Reason: playerDataReasonTooLarge,
					Detail: fmt.Sprintf("体积 %d 超过上限 %d", entryInfo.Size(), playerDataMaxFileBytes), Blocking: false,
				})
			}
		}
	}
	sort.SliceStable(audit.Findings, func(i, j int) bool {
		if audit.Findings[i].Dir == audit.Findings[j].Dir {
			return audit.Findings[i].Name < audit.Findings[j].Name
		}
		return audit.Findings[i].Dir < audit.Findings[j].Dir
	})
	return audit, nil
}

func validPlayerDataName(dir, name string) bool {
	lower := strings.ToLower(name)
	switch dir {
	case "playerdata":
		stem := strings.TrimSuffix(lower, ".dat")
		stem = strings.TrimSuffix(stem, ".dat_old")
		if stem == lower {
			return false
		}
		if len(stem) != 32 || !IsLowerHex(stem, 32) {
			if len(stem) == 36 {
				return validDashedUUID(stem)
			}
			return false
		}
		return true
	case "stats", "advancements":
		if !strings.HasSuffix(lower, ".json") {
			return false
		}
		stem := strings.TrimSuffix(lower, ".json")
		if len(stem) == 32 && IsLowerHex(stem, 32) {
			return true
		}
		if len(stem) == 36 {
			return validDashedUUID(stem)
		}
		return false
	}
	return true
}

func validDashedUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, ch := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}
