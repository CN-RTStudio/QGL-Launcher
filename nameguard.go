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
	nameRejectEmpty      = "empty"                // 去空白后为空
	nameRejectControl    = "control-byte"         // 含 NUL/CR/LF/ESC 等控制字符
	nameRejectSeparator  = "path-separator"       // 含 / 或 \（不允许目录段）
	nameRejectForbidden  = "forbidden-filename-char" // 含 : * ? " < > |
	nameRejectTraversal  = "dot-segment"          // 整段为 . 或 ..
	nameRejectReserved   = "reserved-device-name" // Windows 保留设备名
	nameRejectOuterSpace = "outer-space"          // 前导/尾随空格
	nameRejectOuterDot   = "outer-dot"            // 前导/尾点
	nameRejectInnerSpace = "inner-space"          // 内部含空格（仅用于 loader 标识这类 token 段）
	nameRejectLength     = "too-long"             // 超过单段长度上限
	nameRejectExtension  = "bad-extension"        // mod 文件扩展名不在白名单
	nameRejectInvisible  = "invisible-rune"       // 含零宽 / 软连字符 / BOM 等不可见格式字符
	nameRejectBidi       = "bidi-control"          // 含双向覆写控制字符（U+202A-202E / 2066-2069 等）
	nameRejectNonchar    = "non-character"         // 含 Unicode 非字符（U+FFFE/F、FDD0-FDEF）
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

// mod 落盘扩展名白名单：Modrinth 模组是 .jar；极少量老式 coremod/资源包以 .zip
// 分发；部分启动器用 .jar.disabled 表示“暂不启用”。其余一律拒绝，防止把
// .exe / .bat / .scr 之类借下载通道写进 mods 目录。
var allowedModFileExts = map[string]bool{
	".jar":         true,
	".zip":         true,
	".jar.disabled": true,
}

// containsControlByte 报告字符串是否带 ASCII 控制字节（0x00-0x1F、0x7F）。
// 这些字节不能出现在任何“会落盘 / 会写日志 / 会渲染到界面”的名字里。按原始字节
// 扫描而非 rune：非法 UTF-8 序列里夹带的控制字节也必须被识别（路径安全口径）。
func containsControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
}

// unsafeRuneCode 按 Unicode 码点扫描名字里“肉眼不可见、可用于仿冒 / 终端与日志
// 注入”的格式字符，返回拒绝原因码；安全字符返回 nameRejectNone。
//
// 只列对文件系统名字段确有滥用价值、且在正常昵称 / 版本号里没有合法用途的字符，
// 避免误伤普通中文、emoji 与空格：
//   - nameRejectBidi：双向覆写 / 隔离控制符 U+202A-202E、U+2066-2069。它们能把
//     后续字符的显示顺序反转，典型攻击是把 "evil.exe‮202E" 显示成 "exe.live" 之类，
//     在账户列表 / 下载列表 / 日志里骗过用户眼睛；
//   - nameRejectInvisible：零宽空格 / 连接符（U+200B-200F）、软连字符 U+00AD、
//     蒙古文元音分隔符 U+180E、行 / 段分隔符 U+2028-2029、字连接符与不可见数学
//     运算符 U+2060-2064、废弃格式符 U+206A-206F、BOM / 零宽不换行空格 U+FEFF。
//     这些字符在文件管理器、终端、界面里不可见，却能造出两个看起来相同、实际不同
//     的目录名（同形异义），并可借此让两个账户目录在 UI 上无法区分；
//   - nameRejectNonchar：Unicode 永久非字符 U+FDD0-FDEF 与各平面末尾的
//     U+?FFFE / U+?FFFF。它们不代表任何文字，只用于内部哨兵，绝不该出现在名字里。
func unsafeRuneCode(r rune) string {
	switch {
	case r == 0x202A || r == 0x202B || r == 0x202C || r == 0x202D || r == 0x202E ||
		r == 0x2066 || r == 0x2067 || r == 0x2068 || r == 0x2069:
		return nameRejectBidi
	case r == 0x00AD || r == 0x180E ||
		(r >= 0x200B && r <= 0x200F) ||
		r == 0x2028 || r == 0x2029 ||
		(r >= 0x2060 && r <= 0x2064) ||
		(r >= 0x206A && r <= 0x206F) ||
		r == 0xFEFF:
		return nameRejectInvisible
	case (r >= 0xFDD0 && r <= 0xFDEF):
		return nameRejectNonchar
	}
	// 各平面的 U+?FFFE / U+?FFFF（含基本平面的 U+FFFE/U+FFFF）。
	if low := r & 0xFFFF; low == 0xFFFE || low == 0xFFFF {
		return nameRejectNonchar
	}
	return nameRejectNone
}

// scanUnsafeRunes 返回字符串里第一个不安全码点的原因码；全部安全时返回 nameRejectNone。
