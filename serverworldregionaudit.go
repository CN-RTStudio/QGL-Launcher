package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	wrReasonOK           = "ok"
	wrReasonMissing      = "missing"
	wrReasonUnreadable   = "unreadable"
	wrReasonSymlink      = "symlink"
	wrReasonTooLarge     = "too-large"
	wrReasonTooMany      = "too-many"
	wrReasonShadowRegion = "shadow-region"
	wrReasonUnknownDim   = "unknown-dimension"
	wrReasonSizeBudget   = "world-size-budget"
	wrReasonBadName      = "bad-region-name"

	wrMaxRegionBytes = 512 << 20
	wrMaxRegions     = 2048
	wrMaxWorldBytes  = 8 << 30
	wrMaxDims        = 8
	wrMaxFindings    = 48
)

var wrWorldCandidates = []string{
	"world",
	"world_nether",
	"world_the_end",
	filepath.Join("world", "DIM-1"),
	filepath.Join("world", "DIM1"),
}
var wrRegionDirs = []string{"region", "entities", "poi"}

type WorldRegionFinding struct {
	Path     string
	Reason   string
	Detail   string
	Blocking bool
}
type WorldRegionAudit struct {
	Dir      string
	Worlds   []string
	Regions  int
	Bytes    int64
	Findings []WorldRegionFinding
}

func (a WorldRegionAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WorldRegionFinding) bool { return f.Blocking })
}

func (a WorldRegionAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f WorldRegionFinding) bool { return !f.Blocking && f.Reason != wrReasonOK })
}
func (a WorldRegionAudit) Describe() string {
	return describeTaggedFindings("世界区域文件未发现风险", a.Findings, wrReasonOK, "world", wrMaxFindings,
		func(f WorldRegionFinding) string { return f.Reason },
		func(f WorldRegionFinding) string { return f.Path },
		func(f WorldRegionFinding) string { return f.Detail })
}

func (a *WorldRegionAudit) add(path, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, wrMaxFindings, WorldRegionFinding{Path: path, Reason: reason, Detail: detail, Blocking: blocking})
}

func wrRegionNameOK(name string) bool {
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, ".mca") {
		return false
	}
	stem := strings.TrimSuffix(lower, ".mca")
	parts := strings.Split(stem, ".")
	if len(parts) != 3 || parts[0] != "r" {
		return false
	}
	for _, part := range parts[1:] {
		if part == "" {
			return false
		}
		for _, r := range part {
			if (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

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
