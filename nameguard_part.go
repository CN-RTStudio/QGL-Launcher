package main

import (
	"path/filepath"
	"strings"
)

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
