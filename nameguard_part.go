package main

import (
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
