package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func AuditWorldRegions(worldDir string) (RegionAudit, error) {
	audit := RegionAudit{WorldDir: worldDir}
	candidates := []string{
		filepath.Join(worldDir, "region"),
		filepath.Join(worldDir, "DIM-1", "region"),
		filepath.Join(worldDir, "DIM1", "region"),
	}
	for _, dir := range candidates {
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return audit, err
		}
		audit.RegionDirs++
		if info.Mode()&os.ModeSymlink != 0 {
			audit.Findings = append(audit.Findings, RegionFinding{
				Region: dir, Reason: regionReasonSymlink,
				Detail: "region 目录是符号链接", Blocking: true,
			})
			continue
		}
		if !info.IsDir() {
			audit.Findings = append(audit.Findings, RegionFinding{
				Region: dir, Reason: regionReasonNotRegular,
				Detail: "region 路径不是目录", Blocking: true,
			})
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return audit, err
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			if audit.RegionFiles >= regionMaxFiles {
				audit.Findings = append(audit.Findings, RegionFinding{
					Region: dir, Reason: regionReasonTooMany,
					Detail: fmt.Sprintf("区域文件数量超过 %d", regionMaxFiles), Blocking: true,
				})
				break
			}
			audit.RegionFiles++
			if !regionNamePattern.MatchString(name) {
				audit.Findings = append(audit.Findings, RegionFinding{
					Region: filepath.Join(dir, name), Reason: regionReasonBadName,
					Detail: "文件名不符合 r.X.Z.mca 形态", Blocking: false,
				})
				continue
			}
			audit.inspectRegion(dir, name)
		}
	}
	return audit, nil
}
