package main

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
	return rejectReasonText(why, "整合包清单未通过安全校验", describeMrpackRejectTexts)
}

// mrpackReject 记录一次整合包清单被拦截的安全事件并返回错误。
