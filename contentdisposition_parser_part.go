package main

import (
	"strings"
)

func percentDecode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) {
				return nil, cdErr(CDReasonBadPercent)
			}
			hi := hexVal(s[i+1])
			lo := hexVal(s[i+2])
			if hi < 0 || lo < 0 {
				return nil, cdErr(CDReasonBadPercent)
			}
			out = append(out, byte(hi<<4|lo))
			i += 2
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// ValidateDownloadFilename 对“已从 CD 头选出的文件名”做落盘前安全判定。
// 只裁决名字本身（调用方应保证传入的是纯文件名而非整路径），不含目录拼接。
func ValidateDownloadFilename(name string) error {
	if name == "" {
		return cdErr(CDReasonNoFilename)
	}
	if len(name) > cdMaxFilenameLen {
		return cdErr(CDReasonNameTooLong)
	}
	if strings.IndexByte(name, 0) >= 0 {
		return cdErr(CDReasonNullByte)
	}
	if containsControlByte(name) {
		return cdErr(CDReasonControlChar)
	}
	// 路径分隔：正反斜杠一律拒绝（含编码后还原出的）。
	if strings.ContainsAny(name, "/\\") {
		return cdErr(CDReasonPathSeparator)
	}
	// 盘符：第二字符为冒号，如 C:。
	if len(name) >= 2 && name[1] == ':' {
		return cdErr(CDReasonDriveOrUNC)
	}
	// 其余位置的冒号在 NTFS 上是备用数据流写法（"invoice.pdf:hidden.exe" 会写进
	// invoice.pdf 的隐藏流，主文件名不变，用户在资源管理器里看不出异常）。
	if strings.ContainsRune(name, ':') {
		return cdErr(CDReasonAlternateStream)
	}
	// Win32 文件名非法字符：这些名字落盘会失败或被系统改名，导致"校验过的名字"
	// 与"真正写下去的名字"不一致。
	if strings.ContainsAny(name, `<>"|?*`) {
		return cdErr(CDReasonForbiddenChar)
	}
	// 双向覆写 / 零宽 / 非字符码点：界面上不可见或可反转显示顺序，用来伪装扩展名。
	if scanUnsafeRunes(name) != nameRejectNone {
		return cdErr(CDReasonInvisibleRune)
	}
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || strings.Trim(trimmed, ".") == "" {
		return cdErr(CDReasonDotOrSpace)
	}
	// 前导点（隐藏/Unix 配置文件）或前导空白拒绝；尾随点/空格在 Windows 落盘
	// 会被剥离造成混淆，同样拒绝。
	if name[0] == '.' || name[0] == ' ' || name[len(name)-1] == '.' || name[len(name)-1] == ' ' {
		return cdErr(CDReasonLeadingDotSpace)
	}
	// 路径遍历段。
	if name == ".." || strings.HasPrefix(name, "..") {
		return cdErr(CDReasonTraversal)
	}
	if isReservedDeviceName(stemOfName(name)) {
		return cdErr(CDReasonReservedDevice)
	}
	return nil
}
