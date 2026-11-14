package main

import (
	"bufio"
	"bytes"
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

// Keys 返回所有键（排序），主要用于测试与排查。
