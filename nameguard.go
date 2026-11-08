package main

import (
	"path/filepath"
	"strings"
)

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
func scanUnsafeRunes(s string) string {
	for _, r := range s {
		if code := unsafeRuneCode(r); code != nameRejectNone {
			return code
		}
	}
	return nameRejectNone
}

func containsAnyByte(s string, set string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(set, s[i]) >= 0 {
			return true
		}
	}
	return false
}

// isReservedDeviceName 判断“去掉扩展名后的词干”是否是 Windows 保留设备名。
// Windows 对 CON / PRN / AUX / NUL / COM1..9 / LPT1..9 保留，且：
//   - 大小写不敏感；
//   - 后面跟任意扩展名（CON.txt）仍保留；
//   - 尾随若干点/空格会被系统剥掉后再判断（"CON." / "COM1 " 仍命中）。
func isReservedDeviceName(stem string) bool {
	st := strings.ToUpper(strings.TrimRight(stem, ". "))
	switch st {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(st) == 4 {
		prefix, digit := st[:3], st[3]
		if (prefix == "COM" || prefix == "LPT") && digit >= '1' && digit <= '9' {
			return true
		}
	}
	return false
}

// stemOfName 取“第一个扩展名之前”的词干用于保留设备名判断。
// 例如 "CON.txt" -> "CON"；"nul.jar.disabled" -> "nul"。
func stemOfName(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}

// auditComponent 校验一个“不允许带目录、会直接落盘”的名字段。
// 返回拒绝原因码，nameRejectNone 表示通过。调用前不要再做其它裁剪。
func auditComponent(name string, maxLen int) string {
	if name == "" {
		return nameRejectEmpty
	}
	if strings.TrimSpace(name) == "" {
		return nameRejectEmpty
	}
	if containsControlByte(name) {
		return nameRejectControl
	}
	// 双向覆写 / 零宽 / 非字符等不可见 Unicode：在 ASCII 控制字符之后、结构性
	// 字符判定之前拦截，避免它们借 UTF-8 合法编码绕过字节级检查。
	if code := scanUnsafeRunes(name); code != nameRejectNone {
		return code
	}
	if containsAnyByte(name, `/\`) {
		return nameRejectSeparator
	}
	if containsAnyByte(name, `:*?"<>|`) {
		return nameRejectForbidden
	}
	if name == "." || name == ".." {
		return nameRejectTraversal
	}
	// Windows 会先剥掉尾点/尾空格，再按保留设备名命中（"CON." / "COM1 " 仍指向设备），
	// 因此设备名判定要排在“尾点/尾空格”拒绝之前，用剥过之后的词干判断。
	stripped := strings.TrimRight(name, ". ")
	if isReservedDeviceName(stemOfName(stripped)) {
		return nameRejectReserved
	}
	if name[0] == ' ' || name[len(name)-1] == ' ' {
		return nameRejectOuterSpace
	}
	if name[0] == '.' || name[len(name)-1] == '.' {
		return nameRejectOuterDot
	}
	if len(name) > maxLen {
		return nameRejectLength
	}
	return nameRejectNone
}

// SafeVersionComponent 校验版本目录名（versions/<name>）。
// 只做“去首尾空白”这一确定无害的归一化，其余问题一律拒绝。
// 返回干净名字与拒绝原因码（空串=通过）。
func SafeVersionComponent(name string) (string, string) {
	clean := strings.TrimSpace(name)
	if why := auditComponent(clean, maxVersionComponentLen); why != nameRejectNone {
		return "", why
	}
	return clean, nameRejectNone
}

// SafeAccountName 校验“会成为 Users/<name>/ 目录段”的账户名（微软 / 离线 /
// Yggdrasil 外置登录昵称）。历史上 validateUsername 只挡 ".."、"/"、"\" 与 ASCII
// 控制字符，漏掉了 Windows 保留设备名（CON/NUL/COM1…）、NTFS 备用数据流冒号、
// 其它文件名字符以及不可见 / 双向覆写 Unicode。账户名与凭据文件路径直接拼接，
// 必须与其它落盘段走同一套规则，只是长度上限沿用历史的 64。
// 仅做“去首尾空白”这一确定无害的归一化，其余问题一律拒绝。
func SafeAccountName(name string) (string, string) {
	clean := strings.TrimSpace(name)
	if why := auditComponent(clean, maxAccountNameLen); why != nameRejectNone {
		return "", why
	}
	return clean, nameRejectNone
}


// （"<customName> (<loaderName> <loaderVersion>)"），它同样会成为版本目录名。
func SafeVersionDisplayName(name string) (string, string) {
	clean := strings.TrimSpace(name)
	if why := auditComponent(clean, maxVersionDisplayLen); why != nameRejectNone {
		return "", why
	}
	return clean, nameRejectNone
}

// SafeLoaderComponent 校验加载器名 / 加载器版本这类“内部允许点号”的短标识，
// 例如 fabric / 0.16.10 / 53.0.12。规则与版本名一致，只是长度上限更小。
func SafeLoaderComponent(value string) (string, string) {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return "", nameRejectEmpty
	}
	if why := auditComponent(clean, maxLoaderComponentLen); why != nameRejectNone {
		return "", why
	}
	// fabric / forge / 版本号这类加载器标识来自加载器元数据，是无空格的 token；
	// 内部空格只可能来自异常或伪造数据，拼进展示名 / 路径会引入歧义，单独拒绝。
	if strings.ContainsRune(clean, ' ') {
		return "", nameRejectInnerSpace
	}
	return clean, nameRejectNone
}

// SafeModFileName 校验模组落盘文件名。先强制只取最后一段（服务端文件名里
// 即便带目录也不允许建子目录），再过单段规则，最后要求扩展名在白名单。
// 返回干净文件名与拒绝原因码。
func SafeModFileName(name string) (string, string) {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "", nameRejectEmpty
	}
	if why := auditComponent(base, maxModFileComponentLen); why != nameRejectNone {
		return "", why
	}
	lower := strings.ToLower(base)
	okExt := false
	for ext := range allowedModFileExts {
		if strings.HasSuffix(lower, ext) {
			okExt = true
			break
		}
	}
	if !okExt {
		return "", nameRejectExtension
	}
	return base, nameRejectNone
}

// PickSafeModFileName 按候选顺序挑一个能通过 SafeModFileName 的文件名，
// 全部失败时回退到固定安全名。用于服务端给的主文件名不可信、需要多级兜底的场景。
func PickSafeModFileName(candidates ...string) string {
	for _, c := range candidates {
		if clean, why := SafeModFileName(c); why == nameRejectNone {
			return clean
		}
	}
	return "mod.jar"
}

// describeNameReject 把拒绝原因码转成中文说明，供错误信息/安全事件使用。
func describeNameReject(why string) string {
	switch why {
	case nameRejectEmpty:
		return "名称为空"
	case nameRejectControl:
		return "名称包含非法控制字符"
	case nameRejectSeparator:
		return "名称不允许包含路径分隔符"
	case nameRejectForbidden:
		return "名称包含文件名非法字符 : * ? \" < > |"
	case nameRejectTraversal:
		return "名称不允许为 . 或 .."
	case nameRejectReserved:
		return "名称命中 Windows 保留设备名（CON/PRN/AUX/NUL/COM/LPT）"
	case nameRejectOuterSpace:
		return "名称不允许以空格开头或结尾"
	case nameRejectOuterDot:
		return "名称不允许以点开头或结尾"
	case nameRejectInnerSpace:
		return "加载器标识不允许包含内部空格"
	case nameRejectLength:
		return "名称超过单段长度上限"
	case nameRejectExtension:
		return "模组文件扩展名不在允许列表（.jar/.zip/.jar.disabled）"
	case nameRejectInvisible:
		return "名称包含零宽空格 / 软连字符 / BOM 等不可见字符"
	case nameRejectBidi:
		return "名称包含双向覆写控制字符（可反转显示顺序，用于仿冒）"
	case nameRejectNonchar:
		return "名称包含 Unicode 永久非字符"
	default:
		return "名称未通过安全校验"
	}
}
