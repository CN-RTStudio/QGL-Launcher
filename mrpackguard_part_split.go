package main

import (
	"path/filepath"
	"strings"
)

// cleanMrpackPathSegments 把相对路径拆成已校验的干净段（'/' 连接）。
// 与 zipextract 的 secureZipRelPath 取向一致：不做平台 Clean，逐段手工判定，
// 保证 Windows / Linux 行为相同；这里更严格——空段 / '.' 也直接拒绝（不折叠）。
// 返回干净的 '/'-相对路径与拒绝原因码。
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

// mrpackPathPolicy 在“路径段已合法”的基础上施加实例目录写入策略。
// rel 必须是 cleanMrpackPathSegments 产出的 '/'-相对路径。
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

// mrpackOverridePolicy 针对 overrides/ 解压条目的落盘策略，比 files[] 略宽：
// Modrinth 规范允许覆写目录根部放 options.txt / servers.dat 这类数据文件，
// 因此根部不做“只能白名单子目录”限制，但仍堵住代码执行与私有目录：
//   - QGL/ 任意层级一律拒绝（启动器私有配置）；
//   - 实例目录根部的启动配置 / 可执行（<id>.json、.jar、.exe 等）一律拒绝；
//   - mods/ 只允许 mod 扩展名，resourcepacks/shaderpacks 只允许 .zip；
//   - 其余子目录拒绝可执行 / 脚本（.exe/.bat/.../.jar），但允许 .json 等数据文件。
