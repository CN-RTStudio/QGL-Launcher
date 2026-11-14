package main

import ()

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
