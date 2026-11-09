package main

// nameguard.go —— “落盘名单段”安全内核。
//
// 威胁模型：
//   启动器有大量字符串最终会被拼进文件系统路径，典型链路是
//   前端 / 第三方版本 JSON / Modrinth 元数据 / .mrpack 清单
//       -> customName、loaderName、loaderVersion、mcVersion、mod 文件名
//       -> versions/<name>/<name>.json、versions/<mcVersion>、mods/<file>
//
// 历史上的 sanitizeVersionName 只做 strings.NewReplacer 字符删除，存在以下缺口：
//   1. 控制字符（NUL / CR / LF / ESC 等 0x00-0x1F、0x7F）原样保留，可在日志、
//      下载列表渲染中注入伪造行、终端转义，NUL 还会截断 C 层路径；
//   2. Windows 保留设备名（CON / PRN / AUX / NUL / COM1-9 / LPT1-9，带任意
//      扩展名也算）会把 MkdirAll/Create 导向设备而不是普通文件；
//   3. 纯 "." / ".." 或尾点、尾空格：Windows 会静默剥掉尾点和尾空格，攻击者可
//      用 "foo." 覆盖/混淆已有的 "foo" 目录；纯点段直接造成路径穿越/当前目录写；
//   4. 名字没有长度上限，叠加 versions/<name>/<name>.json 后可能撞 PATH_MAX；
//   5. mod 文件名来自 Modrinth 服务器，filepath.Base 只能剥离目录，挡不住控制
//      字符、保留设备名、NTFS 备用数据流（冒号已在另一条规则内）与错误扩展名。
//
// 本内核统一“拒绝而非静默清洗”：命中规则直接返回原因码，由调用方放弃该次
// 下载/安装并记安全事件，避免“清洗后名字被悄悄改掉、用户以为写进了别处”。

// 拒绝原因码：空串表示通过。
const (
	nameRejectNone       = ""
	nameRejectEmpty      = "empty"                   // 去空白后为空
	nameRejectControl    = "control-byte"            // 含 NUL/CR/LF/ESC 等控制字符
	nameRejectSeparator  = "path-separator"          // 含 / 或 \（不允许目录段）
	nameRejectForbidden  = "forbidden-filename-char" // 含 : * ? " < > |
	nameRejectTraversal  = "dot-segment"             // 整段为 . 或 ..
	nameRejectReserved   = "reserved-device-name"    // Windows 保留设备名
	nameRejectOuterSpace = "outer-space"             // 前导/尾随空格
	nameRejectOuterDot   = "outer-dot"               // 前导/尾点
	nameRejectInnerSpace = "inner-space"             // 内部含空格（仅用于 loader 标识这类 token 段）
	nameRejectLength     = "too-long"                // 超过单段长度上限
	nameRejectExtension  = "bad-extension"           // mod 文件扩展名不在白名单
	nameRejectInvisible  = "invisible-rune"          // 含零宽 / 软连字符 / BOM 等不可见格式字符
	nameRejectBidi       = "bidi-control"            // 含双向覆写控制字符（U+202A-202E / 2066-2069 等）
	nameRejectNonchar    = "non-character"           // 含 Unicode 非字符（U+FFFE/F、FDD0-FDEF）
)

// 账户目录名单独的字节长度上限，沿用历史 validateUsername 的 64，避免把已有合法
// 外置登录名（皮肤站允许较长昵称）挡在门外；其余规则与其它落盘段一致。
const maxAccountNameLen = 64

// 单段长度上限。versions/<name>/<name>.json 同一段名出现两次，必须给完整路径
// 留足余量，因此取 120 而非文件系统极限 255。拼上 loader 后缀的“展示名”最终也会
// 成为版本目录段（versions/<展示名>/<展示名>.json），同一段同样出现两次，因此它
// 必须与普通版本段共用 120 预算，而不是另放一个更宽的上限——否则一个顶到 120 的
// 自定义名再加 loader 后缀就会越过单段预算。mod 文件名含版本号通常较长，给 160。
const (
	maxVersionComponentLen = 120
	maxLoaderComponentLen  = 64
	maxVersionDisplayLen   = 120
	maxModFileComponentLen = 160
)
