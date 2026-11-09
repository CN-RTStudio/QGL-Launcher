package main

import (
	"bytes"
	"fmt"
	"strings"
)

// splitPropertyPair 按第一个 '=' 或 ':' 切分，返回去掉键两侧空白的 key 与原始 value。
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

// Get 返回键对应的第一个值；不存在时 ok 为 false。
func (p *serverProperties) Get(key string) (string, bool) {
	for _, ln := range p.lines {
		if ln.isPair && ln.key == key {
			return ln.value, true
		}
	}
	return "", false
}

// Set 把键设置为 value：已存在则原地更新第一个并移除后续重复键，
// 不存在则在末尾追加（沿用 '=' 分隔符）。
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
