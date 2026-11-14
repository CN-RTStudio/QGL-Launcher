package main

import ()

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

// mod 落盘扩展名白名单：Modrinth 模组是 .jar；极少量老式 coremod/资源包以 .zip
// 分发；部分启动器用 .jar.disabled 表示“暂不启用”。其余一律拒绝，防止把
// .exe / .bat / .scr 之类借下载通道写进 mods 目录。
var allowedModFileExts = map[string]bool{
	".jar":          true,
	".zip":          true,
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
