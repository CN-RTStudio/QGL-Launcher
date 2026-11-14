package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func AuditServerWorldRegions(serverDir string) WorldRegionAudit {
	audit := WorldRegionAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("", wrReasonMissing, "服务器目录不存在", true)
		return audit
	}
	dims := 0
	for _, candidate := range wrWorldCandidates {
		root := filepath.Join(serverDir, candidate)
		info, err := os.Lstat(root)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(candidate, wrReasonSymlink, "世界目录是符号链接", true)
			continue
		}
		if !info.IsDir() {
			continue
		}
		dims++
		if dims > wrMaxDims {
			audit.add(candidate, wrReasonUnknownDim, "世界维度数量超过预算", true)
			continue
		}
		audit.Worlds = append(audit.Worlds, candidate)
		for _, regionDir := range wrRegionDirs {
			wrScanRegionDir(&audit, root, regionDir)
		}
		levelDat := filepath.Join(root, "level.dat")
		if info, err := os.Lstat(levelDat); err == nil && info.Mode()&os.ModeSymlink != 0 {
			audit.add(filepath.Join(candidate, "level.dat"), wrReasonSymlink, "level.dat 是符号链接", true)
		}
		if info, err := os.Lstat(levelDat + "_old"); err == nil && !info.IsDir() {
			audit.add(filepath.Join(candidate, "level.dat_old"), wrReasonShadowRegion, "存在 level.dat 旧副本", false)
		}
	}
	if audit.Bytes > wrMaxWorldBytes {
		audit.add("", wrReasonSizeBudget, fmt.Sprintf("世界总体积 %d 字节超过预算", audit.Bytes), false)
	}
	if len(audit.Worlds) == 0 && len(audit.Findings) == 0 {
		audit.add("", wrReasonOK, "未发现世界存档", false)
	}
	if len(audit.Findings) == 0 {
		audit.add("", wrReasonOK, "世界区域文件未发现风险", false)
	}
	return audit
}
