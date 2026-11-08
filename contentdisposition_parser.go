package main

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

func (p *cdParser) skipOWS() {
	for !p.atEnd() {
		c := p.s[p.i]
		if c == ' ' || c == '\t' {
			p.i++
			continue
		}
		break
	}
}

// readToken 读取 RFC 7230 token（1*tchar）。
func (p *cdParser) readToken() string {
	start := p.i
	for !p.atEnd() {
		c := p.s[p.i]
		if isTokenChar(c) {
			p.i++
			continue
		}
		break
	}
	return p.s[start:p.i]
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// readValue 读取参数值：quoted-string 或 token。
func (p *cdParser) readValue() (string, bool) {
	if p.atEnd() {
		return "", false
	}
	if p.peek() == '"' {
		return p.readQuoted()
	}
	// token 形式：读到 ';' 或空白结束。
	start := p.i
	for !p.atEnd() {
		c := p.s[p.i]
		if c == ';' || c == ' ' || c == '\t' {
			break
		}
		if c == '"' { // token 中途出现引号属于畸形
			return "", false
		}
		p.i++
	}
	return p.s[start:p.i], true
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

// decodeFilenameStar 解析 RFC 5987 形式：charset'lang'value（value 为百分号编码）。
// 仅接受 UTF-8 / US-ASCII 字符集，且解码结果必须是合法 UTF-8。
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
