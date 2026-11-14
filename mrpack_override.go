package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func mrpackOverridePolicy(rel string, isDir bool) string {
	if isDir {
		// 目录本身只要段合法即可；QGL 目录由“其下文件命中”即可整体阻断，
		// 这里对纯目录条目也直接拒绝，避免落地空的 QGL 目录。
		top := strings.SplitN(rel, "/", 2)[0]
		if top == mrpackPrivateSubroot {
			return mrpRejectPrivateDir
		}
		return mrpRejectNone
	}
	segs := strings.Split(rel, "/")
	top := segs[0]
	if top == mrpackPrivateSubroot {
		return mrpRejectPrivateDir
	}
	base := segs[len(segs)-1]
	lower := strings.ToLower(base)
	ext := strings.ToLower(filepath.Ext(base))

	if len(segs) == 1 {
		if mrpackSensitiveRootExts[ext] {
			return mrpRejectRootSensitive
		}
		return mrpRejectNone
	}
	switch top {
	case "mods":
		if !allowedModFileExts[lowerExt(lower)] {
			return mrpRejectBadExt
		}
	case "resourcepacks", "shaderpacks":
		if !mrpackPackArchiveExts[ext] {
			return mrpRejectBadExt
		}
	default:
		if mrpackRunnableExts[ext] {
			return mrpRejectBadExt
		}
	}
	return mrpRejectNone
}

func validateMrpackPlannedEntries(plan []zipPlannedEntry) error {
	for _, pe := range plan {
		if why := mrpackOverridePolicy(pe.rel, pe.dir); why != mrpRejectNone {
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
				"mrpackguard", describeMrpackReject(why)+"：overrides/"+pe.rel)
			return fmt.Errorf("%s: overrides/%s", describeMrpackReject(why), pe.rel)
		}
	}
	return nil
}

// lowerExt 返回文件名（已小写）命中的扩展名；对 ".jar.disabled" 这类复合扩展优先返回它。
func lowerExt(lowerName string) string {
	for ext := range allowedModFileExts {
		if strings.HasSuffix(lowerName, ext) {
			return ext
		}
	}
	return filepath.Ext(lowerName)
}
