package main

// mrpackguard.go —— 不可信 .mrpack（Modrinth 整合包）清单结构与落盘路径安全内核。
//
// 威胁模型：
//   .mrpack 来自任意第三方下载源，modrinth.index.json 完全由打包者控制。下载完的
//   files[] 会被写进“版本实例目录”，overrides/ 也会解压到同一目录。这里有两类旧缺口：
//
//   1. 启动配置覆盖 -> 代码执行：实例目录里同时放着启动器信任的启动配置
//      versions/<id>/<id>.json（mainClass / libraries / 启动参数）与可能的同名 jar。
//      历史实现对 files[].path 只做“是否含 .. / NUL”的旧 safeJoin 判定，对 overrides
//      只防 Zip Slip / 符号链接 / 炸弹。恶意整合包可以把一个条目命名成实例目录根部的
//      <id>.json，把 mainClass 指向随包带入的恶意类。更关键的是：清单里的
//      sha1/sha512 由打包者自己填写，只保证“下载内容与清单一致”，不是信任锚——
//      打包者同时控制内容与哈希，校验通过毫无意义。下次用该版本启动即 RCE。
//
//   2. 清单字段畸形 -> 拖垮 / 混淆：files 数量无上限、downloads 镜像数量无上限且不去重、
//      fileSize 可以为负、哈希算法名与十六进制不校验、formatVersion/game 不检查、
//      dependencies 可塞任意键。单个畸形清单可以制造海量无效下载尝试，或把奇怪值
//      拼进后续 URL / 路径。
//
// 本内核“拒绝而非静默清洗”：任何字段越界都返回原因码，由安装流程整体中止并记安全事件。
// 路径策略复用 nameguard 的单段规则，避免重复实现保留设备名 / 控制字符 / 尾点空格判定。

// 清单规模上限。正常整合包远小于此，只有刻意制造的畸形 / 轰炸清单才会触发。
// 阈值刻意从宽（与仓内“宁可炸磁盘也不误限正常数据”的取向一致），但必须是有限值。
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

// files[] 允许写入的实例子目录白名单。Modrinth 整合包的数据文件只该落在这些目录，
// 绝不该出现在实例目录根部（根部是启动配置 / jar 所在地）。
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

// 启动器私有目录：绝不允许整合包写入（QGL/ 存放 config.json、umfs_cache.json 等）。
const mrpackPrivateSubroot = "QGL"

// 实例目录根部命中即拒绝的扩展名：启动配置、可执行 / 脚本文件。
var mrpackSensitiveRootExts = map[string]bool{
	".json": true, ".jar": true, ".exe": true, ".bat": true,
	".cmd": true, ".ps1": true, ".sh": true, ".com": true, ".scr": true,
}

// mods 目录允许的扩展名（复用 nameguard 的 mod 扩展名白名单）。
// resourcepacks / shaderpacks 只允许 .zip；其余子目录允许任意数据文件（.json 配置等）。
var mrpackPackArchiveExts = map[string]bool{".zip": true}

// mrpack 拒绝原因码（空串表示通过）。
const (
	mrpRejectNone         = ""
	mrpRejectEmptyPath    = "empty-path"
	mrpRejectControl      = "control-byte"
	mrpRejectBackslash    = "backslash"
	mrpRejectAbsolute     = "absolute-path"
	mrpRejectDrive        = "drive-prefix"
	mrpRejectBadSegment   = "bad-segment"
	mrpRejectPathTooLong  = "path-too-long"
	mrpRejectPrivateDir   = "private-subroot"
	mrpRejectRootFile     = "root-file"
	mrpRejectRootSensitive = "sensitive-root-file"
	mrpRejectBadExt       = "bad-extension"
	mrpRejectFormat       = "bad-format-version"
	mrpRejectGame         = "bad-game"
	mrpRejectNameControl  = "name-control"
	mrpRejectNameTooLong  = "name-too-long"
	mrpRejectTooManyFiles = "too-many-files"
	mrpRejectNoHash       = "missing-hash"
	mrpRejectBadHashAlg   = "bad-hash-algorithm"
	mrpRejectBadHashValue = "bad-hash-value"
	mrpRejectNoDownload   = "missing-download"
	mrpRejectTooManyURLs  = "too-many-downloads"
	mrpRejectURLScheme    = "url-not-https"
	mrpRejectURLUserInfo  = "url-userinfo"
	mrpRejectURLHost      = "url-bad-host"
	mrpRejectURLPrivate   = "url-private-host"
	mrpRejectURLTooLong   = "url-too-long"
	mrpRejectURLDup       = "duplicate-download"
	mrpRejectBadFileSize  = "bad-file-size"
	mrpRejectDepKey       = "bad-dependency-key"
)
