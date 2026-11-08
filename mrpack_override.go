package main

import (
	"encoding/hex"
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

// validateMrpackPlannedEntries 对 overrides 的解压计划逐条施加 mrpackOverridePolicy。
// rel 必须已经过 zipextract 的 secureZipRelPath 段校验（zipPlannedEntry.rel 即此形态）。
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

// secureMrpackDestRel 校验并返回可安全拼接到实例目录的 '/'-相对路径。
func secureMrpackDestRel(raw string) (string, string) {
	clean, why := cleanMrpackPathSegments(raw)
	if why != mrpRejectNone {
		return "", why
	}
	if why := mrpackPathPolicy(clean); why != mrpRejectNone {
		return "", why
	}
	return clean, mrpRejectNone
}

// secureMrpackDest 把相对路径安全拼接到实例根目录，并做落盘前的“必须在根内”第二道复核。
func secureMrpackDest(baseDir, raw string) (string, error) {
	rel, why := secureMrpackDestRel(raw)
	if why != mrpRejectNone {
		return "", fmt.Errorf("%s: %s", describeMrpackReject(why), raw)
	}
	dest := filepath.Join(baseDir, filepath.FromSlash(rel))
	if !PathWithinRoot(dest, baseDir) {
		return "", fmt.Errorf("整合包文件解析后越出实例目录: %s", raw)
	}
	return dest, nil
}

// validateMrpackHash 校验单个文件的哈希表：键只能是 sha1/sha512，值必须是对应长度的
// 合法十六进制，且至少提供一个。返回错误原因码。
func validateMrpackHash(hashes map[string]string) string {
	if len(hashes) == 0 {
		return mrpRejectNoHash
	}
	for alg, val := range hashes {
		var wantLen int
		switch alg {
		case "sha1":
			wantLen = 40
		case "sha512":
			wantLen = 128
		default:
			return mrpRejectBadHashAlg
		}
		v := strings.TrimSpace(val)
		if len(v) != wantLen {
			return mrpRejectBadHashValue
		}
		if _, err := hex.DecodeString(v); err != nil {
			return mrpRejectBadHashValue
		}
	}
	if _, ok := hashes["sha1"]; !ok {
		if _, ok512 := hashes["sha512"]; !ok512 {
			return mrpRejectNoHash
		}
	}
	return mrpRejectNone
}
