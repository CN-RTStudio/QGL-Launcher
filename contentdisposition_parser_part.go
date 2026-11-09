package main

import (
	"fmt"
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

// ResolveDownloadFilename 解析头并选出一个“已通过安全判定”的文件名；
// filename* 与 filename 都不安全时返回错误，调用方应改用受控的备用名。
func ResolveDownloadFilename(header string) (string, error) {
	res, err := ParseContentDisposition(header)
	if err != nil {
		return "", err
	}
	name := res.PreferredFilename()
	if name == "" {
		return "", cdErr(CDReasonNoFilename)
	}
	// 只取最后一段，纵深防御：即便解码出分隔符也会在 Validate 中被拒，这里不
	// 静默截断（截断可能改变扩展名语义），直接交给 Validate 拒绝。
	if err := ValidateDownloadFilename(name); err != nil {
		return "", err
	}
	return name, nil
}

type cdErrT struct{ code string }

func (e *cdErrT) Error() string { return e.code }
func cdErr(code string) error   { return &cdErrT{code: code} }

// CDReason 从错误中取原因码，非 CD 错误返回空串。
func CDReason(err error) string {
	if e, ok := err.(*cdErrT); ok {
		return e.code
	}
	return ""
}

// DescribeCDReason 排障可读文本。
func DescribeCDReason(code string) string {
	switch code {
	case CDReasonEmpty:
		return "Content-Disposition 头为空"
	case CDReasonMalformed:
		return "Content-Disposition 参数格式非法"
	case CDReasonUnsafeCharset:
		return "filename* 使用了非 UTF-8 字符集"
	case CDReasonBadPercent:
		return "filename* 百分号解码失败或含非法 UTF-8"
	case CDReasonNoFilename:
		return "未提供可用文件名"
	case CDReasonPathSeparator:
		return "文件名包含路径分隔符"
	case CDReasonDriveOrUNC:
		return "文件名包含盘符（疑似绝对路径/UNC）"
	case CDReasonReservedDevice:
		return "文件名命中系统保留设备名"
	case CDReasonControlChar:
		return "文件名包含控制字符"
	case CDReasonTraversal:
		return "文件名包含路径遍历段"
	case CDReasonNameTooLong:
		return "文件名过长"
	case CDReasonDotOrSpace:
		return "文件名仅由点或空白组成"
	case CDReasonLeadingDotSpace:
		return "文件名带前导/尾随点或空白"
	case CDReasonNullByte:
		return "文件名包含 NUL 字节"
	case CDReasonAlternateStream:
		return "文件名包含 NTFS 备用数据流写法（冒号）"
	case CDReasonForbiddenChar:
		return "文件名包含 Windows 非法字符"
	case CDReasonInvisibleRune:
		return "文件名包含不可见/双向覆写字符"
	case CDReasonDuplicateParam:
		return "Content-Disposition 重复给出 filename 参数"
	default:
		return fmt.Sprintf("未知 Content-Disposition 原因码: %s", code)
	}
}
