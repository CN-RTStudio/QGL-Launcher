package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// describeMrpackReject 把拒绝原因码转成中文说明。
func describeMrpackReject(why string) string {
	switch why {
	case mrpRejectEmptyPath:
		return "文件路径为空"
	case mrpRejectControl:
		return "文件路径包含非法控制字符"
	case mrpRejectBackslash:
		return "文件路径必须使用 '/' 分隔，不允许反斜杠"
	case mrpRejectAbsolute:
		return "文件路径不允许以 '/' 开头"
	case mrpRejectDrive:
		return "文件路径不允许带盘符 / UNC"
	case mrpRejectBadSegment:
		return "文件路径含空段、'.'、'..' 或非法目录名"
	case mrpRejectPathTooLong:
		return "文件路径超过长度上限"
	case mrpRejectPrivateDir:
		return "整合包不允许写入启动器私有目录 QGL/"
	case mrpRejectRootFile:
		return "整合包文件不允许直接写在实例目录根部（仅允许白名单子目录）"
	case mrpRejectRootSensitive:
		return "拒绝在实例目录根部写入启动配置 / 可执行 / 脚本文件"
	case mrpRejectBadExt:
		return "文件扩展名不被该目录允许"
	case mrpRejectFormat:
		return "formatVersion 必须为 1"
	case mrpRejectGame:
		return "game 必须为 minecraft"
	case mrpRejectNameControl:
		return "整合包名称包含非法控制字符"
	case mrpRejectNameTooLong:
		return "整合包名称过长"
	case mrpRejectTooManyFiles:
		return "清单声明的文件数量超过上限"
	case mrpRejectNoHash:
		return "文件缺少 sha1/sha512 完整性哈希"
	case mrpRejectBadHashAlg:
		return "哈希算法只允许 sha1/sha512"
	case mrpRejectBadHashValue:
		return "哈希值不是合法的十六进制或长度不符"
	case mrpRejectNoDownload:
		return "文件没有可用的下载地址"
	case mrpRejectTooManyURLs:
		return "单文件下载镜像数量超过上限"
	case mrpRejectURLScheme:
		return "下载地址必须使用 https://"
	case mrpRejectURLUserInfo:
		return "下载地址不允许携带用户信息(userinfo)"
	case mrpRejectURLHost:
		return "下载地址缺少有效主机名"
	case mrpRejectURLPrivate:
		return "下载地址指向内网 / 回环地址"
	case mrpRejectURLTooLong:
		return "下载地址超过长度上限"
	case mrpRejectURLDup:
		return "下载地址存在重复镜像"
	case mrpRejectBadFileSize:
		return "fileSize 为负数或超过单文件上限"
	case mrpRejectDepKey:
		return "dependencies 含不被识别的依赖键"
	default:
		return "整合包清单未通过安全校验"
	}
}

// mrpackReject 记录一次整合包清单被拦截的安全事件并返回错误。
func mrpackReject(why, detail string) error {
	recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
		"mrpackguard", describeMrpackReject(why)+"："+detail)
	return fmt.Errorf("%s", describeMrpackReject(why))
}

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
