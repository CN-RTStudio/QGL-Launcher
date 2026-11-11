package main

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

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
func CDReason(err error) string {
	if e, ok := err.(*cdErrT); ok {
		return e.code
	}
	return ""
}

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

func (p *cdParser) readQuoted() (string, bool) {
	if p.next() != '"' {
		return "", false
	}
	var b strings.Builder
	for !p.atEnd() {
		c := p.next()
		if c == '"' {
			return b.String(), true
		}
		if c == '\\' {
			// quoted-pair：反斜杠只能转义一个可见字符。
			if p.atEnd() {
				return "", false
			}
			q := p.next()
			if q <= 0x20 || q == 0x7f {
				return "", false
			}
			b.WriteByte(q)
			continue
		}
		if c == '\r' || c == '\n' {
			return "", false
		}
		// RFC 7230 quoted-string 只允许 HTAB 这唯一一个控制字符（text 里不含
		// CR/LF，也不允许 NUL 与其它 C0）；旧实现只拒 CR/LF，其余 0x00-0x1F
		// 会原样进入文件名。
		if (c < 0x20 && c != '\t') || c == 0x7F {
			return "", false
		}
		b.WriteByte(c)
	}
	return "", false // 未闭合
}

func decodeFilenameStar(v string) (string, error) {
	q1 := strings.IndexByte(v, '\'')
	if q1 < 0 {
		return "", cdErr(CDReasonMalformed)
	}
	rest := v[q1+1:]
	q2 := strings.IndexByte(rest, '\'')
	if q2 < 0 {
		return "", cdErr(CDReasonMalformed)
	}
	charset := strings.ToLower(strings.TrimSpace(v[:q1]))
	encoded := rest[q2+1:]
	if charset != "utf-8" && charset != "us-ascii" && charset != "" {
		return "", cdErr(CDReasonUnsafeCharset)
	}
	decoded, err := percentDecode(encoded)
	if err != nil {
		return "", err
	}
	// 非法 UTF-8 拒绝（US-ASCII 是 UTF-8 子集）。
	if !utf8.Valid(decoded) {
		return "", cdErr(CDReasonBadPercent)
	}
	return string(decoded), nil
}
