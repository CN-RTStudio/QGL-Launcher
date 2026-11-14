package main

import (
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
