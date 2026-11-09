package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func wrScanRegionDir(audit *WorldRegionAudit, root, rel string) {
	entries, err := os.ReadDir(filepath.Join(root, rel))
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		audit.add(rel, wrReasonUnreadable, "区域目录不可读", true)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			audit.add(filepath.Join(rel, entry.Name()), wrReasonUnknownDim, "区域目录下出现嵌套目录", false)
			continue
		}
		name := entry.Name()
		relFile := filepath.Join(rel, name)
		info, err := os.Lstat(filepath.Join(root, rel, name))
		if err != nil {
			audit.add(relFile, wrReasonUnreadable, "无法读取区域文件属性", true)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(relFile, wrReasonSymlink, "区域文件是符号链接", true)
			continue
		}
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".mca_old") || strings.HasSuffix(lower, ".mca.bak") ||
			strings.HasSuffix(lower, ".mcr") {
			audit.add(relFile, wrReasonShadowRegion, "存在旧的区域文件副本", false)
			continue
		}
		if !wrRegionNameOK(name) {
			audit.add(relFile, wrReasonBadName, "区域文件名不符合 r.x.z.mca 规范", false)
			continue
		}
		if info.Size() > wrMaxRegionBytes {
			audit.add(relFile, wrReasonTooLarge, "单个区域文件超过体积预算", true)
		}
		audit.Regions++
		audit.Bytes += info.Size()
		if audit.Regions >= wrMaxRegions {
			audit.add(rel, wrReasonTooMany, "区域文件数量超过预算", true)
			return
		}
	}
}

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
