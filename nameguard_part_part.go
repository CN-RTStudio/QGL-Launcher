package main

import "strings"

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
