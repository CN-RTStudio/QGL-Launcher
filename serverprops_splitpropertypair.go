package main

import (
	"bytes"
	"fmt"
	"strings"
)

func splitPropertyPair(line string) (key, value string, sep byte, ok bool) {
	eq := strings.IndexByte(line, '=')
	co := strings.IndexByte(line, ':')
	idx := eq
	if idx < 0 || (co >= 0 && co < idx) {
		idx = co
	}
	if idx < 0 {
		return "", "", 0, false
	}
	key = strings.TrimSpace(line[:idx])
	if key == "" {
		return "", "", 0, false
	}
	return key, line[idx+1:], line[idx], true
}
func (p *serverProperties) Get(key string) (string, bool) {
	for _, ln := range p.lines {
		if ln.isPair && ln.key == key {
			return ln.value, true
		}
	}
	return "", false
}

func (p *serverProperties) Set(key, value string) {
	first := -1
	kept := p.lines[:0]
	for _, ln := range p.lines {
		if ln.isPair && ln.key == key {
			if first < 0 {
				ln.value = value
				first = len(kept)
				kept = append(kept, ln)
			}
			// 重复键：丢弃后续行，避免冲突。
			continue
		}
		kept = append(kept, ln)
	}
	p.lines = kept
	if first < 0 {
		p.lines = append(p.lines, propLine{isPair: true, key: key, value: value, sep: '='})
	}
}

// Marshal 用 LF 序列化；键值做最小合法性校验，注释/空行原样输出。
func (p *serverProperties) Marshal() []byte {
	var b bytes.Buffer
	for _, ln := range p.lines {
		if !ln.isPair {
			b.WriteString(ln.raw)
			b.WriteByte('\n')
			continue
		}
		fmt.Fprintf(&b, "%s%c%s\n", ln.key, ln.sep, ln.value)
	}
	return b.Bytes()
}
