package main

import (
	"fmt"
)

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
