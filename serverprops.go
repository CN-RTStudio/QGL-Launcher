package main

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// server.properties 是 java.util.Properties 风格的文本：
//   - 以 # 或 ! 开头的是注释，空行忽略；
//   - 键值分隔符是第一个 '=' 或 ':'（Properties 两种都接受）；
//   - 行尾的 \r 需要容忍（Windows 编辑器常写 CRLF）。
//
// 旧实现用 strings.Split(content,"\n") 后逐行 HasPrefix 再整体 Join，存在三个问题：
//  1. 同键出现多次时只改第一行，序列化后留下互相冲突的重复键，最终生效值取决于解析顺序；
//  2. CRLF 文件里键名会带 '\r'，HasPrefix 可能匹配不到而重复追加；
//  3. 不校验写入的值，配置注入风险依赖调用方自觉。
//
// 这里做一个保序、保留注释、只动目标键的最小安全读写器。

// propLine 表示 properties 文件里的一行。
// isPair 为 true 时该行是 key=value；否则原样保留（注释 / 空行 / 无法解析行）。
type propLine struct {
	isPair bool
	key    string
	value  string
	sep    byte // '=' 或 ':'
	raw    string
}

// serverProperties 保留行顺序，Set 才能在不打乱注释与其它配置的前提下原地改写。
type serverProperties struct {
	lines []propLine
}

// parseServerProperties 从字节内容解析 properties。容忍 CRLF / LF。
func parseServerProperties(data []byte) *serverProperties {
	p := &serverProperties{}
	s := bufio.NewScanner(bytes.NewReader(data))
	// 默认 Scanner 每行有长度上限，配置行一般很短，给足 1 MiB 与其它配置读取保持一致。
	s.Buffer(make([]byte, 0, 64*1024), maxServerLogLineBytes)
	for s.Scan() {
		line := strings.TrimRight(s.Text(), "\r")
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == '!' {
			p.lines = append(p.lines, propLine{isPair: false, raw: line})
			continue
		}
		key, value, sep, ok := splitPropertyPair(line)
		if !ok {
			// 既不是注释也没有合法分隔符：原样保留，不擅自删除用户内容。
			p.lines = append(p.lines, propLine{isPair: false, raw: line})
			continue
		}
		p.lines = append(p.lines, propLine{isPair: true, key: key, value: value, sep: sep})
	}
	return p
}

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
