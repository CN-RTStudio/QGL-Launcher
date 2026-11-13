package main

import (
	"path/filepath"
	"strings"
)

func cleanMrpackPathSegments(raw string) (string, string) {
	if raw == "" {
		return "", mrpRejectEmptyPath
	}
	if containsControlByte(raw) {
		return "", mrpRejectControl
	}
	if strings.ContainsRune(raw, '\\') {
		return "", mrpRejectBackslash
	}
	if strings.HasPrefix(raw, "/") {
		return "", mrpRejectAbsolute
	}
	// 盘符（C:x / C:/x）与 UNC（//host/share）在更前面已被前导 '/' 与盘符规则覆盖，
	// 这里再兜底一次任何位置的 "x:" 段前缀。
	if len(raw) >= 2 && raw[1] == ':' {
		return "", mrpRejectDrive
	}

	var segs []string
	for _, seg := range strings.Split(raw, "/") {
		switch seg {
		case "", ".", "..":
			return "", mrpRejectBadSegment
		}
		// 复用 nameguard 单段规则：保留设备名 / 控制字符 / 尾点尾空格 / 非法文件名字符。
		if why := auditComponent(seg, maxMrpackSegmentLen); why != nameRejectNone {
			return "", mrpRejectBadSegment
		}
		segs = append(segs, seg)
	}
	clean := strings.Join(segs, "/")
	if len(clean) > maxMrpackRelPathLen {
		return "", mrpRejectPathTooLong
	}
	return clean, mrpRejectNone
}

func mrpackPathPolicy(rel string) string {
	segs := strings.Split(rel, "/")
	top := segs[0]

	if top == mrpackPrivateSubroot {
		return mrpRejectPrivateDir
	}
	// 只有一级（直接位于实例目录根部）的文件一律拒绝：files[] 只允许落到白名单子目录，
	// 根部是 <id>.json / <id>.jar 等启动信任文件所在地。
	if len(segs) == 1 {
		return mrpRejectRootFile
	}
	if !mrpackAllowedSubroots[top] {
		return mrpRejectRootFile
	}

	base := segs[len(segs)-1]
	lower := strings.ToLower(base)
	ext := strings.ToLower(filepath.Ext(base))

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
		// config / kubejs / scripts 等目录允许数据文件，但根部敏感扩展名策略对
		// 任意层级的可执行 / 脚本仍生效，防止借子目录落 .jar / .exe。
		if mrpackSensitiveRootExts[ext] && ext != ".json" {
			return mrpRejectBadExt
		}
	}
	return mrpRejectNone
}

// 任意目录都不允许借整合包落地的可执行 / 脚本扩展名（.json 不在其中：config 等目录
// 里大量存在合法 .json 配置；根部 .json 由 mrpackSensitiveRootExts 单独拒绝）。
var mrpackRunnableExts = map[string]bool{
	".exe": true, ".bat": true, ".cmd": true, ".ps1": true,
	".sh": true, ".com": true, ".scr": true, ".vbs": true, ".jar": true,
}
