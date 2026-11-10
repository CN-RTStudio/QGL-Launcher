package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	// maxMrpackIndexFiles 单个清单允许声明的文件条目数上限。
	maxMrpackIndexFiles = 20000
	// maxMrpackMirrorsPerFile 单个文件允许给出的下载镜像数上限（Modrinth 正常只给 1 个）。
	maxMrpackMirrorsPerFile = 20
	// maxMrpackRelPathLen 落盘相对路径总长度上限（给前面的实例目录绝对路径留余量）。
	maxMrpackRelPathLen = 512
	// maxMrpackSegmentLen 路径单段长度上限，复用 nameguard 的保守取向。
	maxMrpackSegmentLen = maxModFileComponentLen
	// maxMrpackDownloadURLLen 单个下载 URL 长度上限，防超长 URL 拖慢解析与日志。
	maxMrpackDownloadURLLen = 2048
	// maxMrpackNameLen 整合包展示名长度上限（仅展示，不进路径）。
	maxMrpackNameLen = 200
	// maxMrpackDeclaredFileSize 清单声明的单文件体积上限；与整合包本体 8GiB 上限对齐。
	maxMrpackDeclaredFileSize = maxMrpackDownloadBytes
)

var mrpackAllowedSubroots = map[string]bool{
	"mods":           true,
	"resourcepacks":  true,
	"shaderpacks":    true,
	"config":         true,
	"defaultconfigs": true,
	"kubejs":         true,
	"scripts":        true,
	"patch":          true,
}

const mrpackPrivateSubroot = "QGL"

var mrpackSensitiveRootExts = map[string]bool{
	".json": true, ".jar": true, ".exe": true, ".bat": true,
	".cmd": true, ".ps1": true, ".sh": true, ".com": true, ".scr": true,
}

var mrpackPackArchiveExts = map[string]bool{".zip": true}

// mrpack 拒绝原因码（空串表示通过）。
const (
	mrpRejectNone          = ""
	mrpRejectEmptyPath     = "empty-path"
	mrpRejectControl       = "control-byte"
	mrpRejectBackslash     = "backslash"
	mrpRejectAbsolute      = "absolute-path"
	mrpRejectDrive         = "drive-prefix"
	mrpRejectBadSegment    = "bad-segment"
	mrpRejectPathTooLong   = "path-too-long"
	mrpRejectPrivateDir    = "private-subroot"
	mrpRejectRootFile      = "root-file"
	mrpRejectRootSensitive = "sensitive-root-file"
	mrpRejectBadExt        = "bad-extension"
	mrpRejectFormat        = "bad-format-version"
	mrpRejectGame          = "bad-game"
	mrpRejectNameControl   = "name-control"
	mrpRejectNameTooLong   = "name-too-long"
	mrpRejectTooManyFiles  = "too-many-files"
	mrpRejectNoHash        = "missing-hash"
	mrpRejectBadHashAlg    = "bad-hash-algorithm"
	mrpRejectBadHashValue  = "bad-hash-value"
	mrpRejectNoDownload    = "missing-download"
	mrpRejectTooManyURLs   = "too-many-downloads"
	mrpRejectURLScheme     = "url-not-https"
	mrpRejectURLUserInfo   = "url-userinfo"
	mrpRejectURLHost       = "url-bad-host"
	mrpRejectURLPrivate    = "url-private-host"
	mrpRejectURLTooLong    = "url-too-long"
	mrpRejectURLDup        = "duplicate-download"
	mrpRejectBadFileSize   = "bad-file-size"
	mrpRejectDepKey        = "bad-dependency-key"
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
