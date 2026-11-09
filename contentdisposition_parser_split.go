package main

import (
	"strings"
	"unicode/utf8"
)

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
