package main

import (
	"strings"
)

const (
	// httpDiagDefaultSnippetBytes 是错误响应体摘要的默认上限：诊断用途，4KiB 足够。
	httpDiagDefaultSnippetBytes = 4096
	// httpDiagMaxSnippetBytes 是调用方可指定上限的天花板，防止误传一个巨大值。
	httpDiagMaxSnippetBytes = 64 * 1024
)

// sanitizeSnippet 把错误响应体净化为安全的单行文本：
//   - 剥除终端转义序列：CSI（ESC[ … 终止字节）与 OSC（ESC] … BEL/ST），
//     以及 ESC 后随单字节的两字节序列，防止控制台颜色/标题注入；
//   - 其余 C0 控制字符（含 CR/LF/Tab/NUL）与 DEL 一律替换为空格，杜绝换行伪造日志行；
//   - 折叠连续空白并去除首尾空白。
//
// 按字节处理：所有被删除/替换的字节都 <0x80，高位字节（UTF-8 续/首字节）原样保留，
// 不会破坏多字节 UTF-8 序列。
func sanitizeSnippet(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))
	n := len(raw)
	i := 0
	for i < n {
		c := raw[i]
		switch {
		case c == 0x1b && i+1 < n:
			// 终端转义序列：整段丢弃，不让 ESC 或其参数流到日志/终端。
			switch raw[i+1] {
			case '[':
				// CSI：ESC[ 参数(0x20-0x3f)* 终止(0x40-0x7e)。
				j := i + 2
				for j < n && raw[j] >= 0x20 && raw[j] <= 0x3f {
					j++
				}
				if j < n && raw[j] >= 0x40 && raw[j] <= 0x7e {
					j++ // 吃掉终止字节
				}
				i = j
				continue
			case ']':
				// OSC：ESC] 后任意内容，直到 BEL 或 ST(ESC \)。
				// 旧实现遇到终止符后直接 j=n，会把 OSC 之后的正文（如
				// "...title\aprompt> " 里的 "prompt> "）一并吞掉，诊断摘要被清空。
				j := i + 2
				for j < n {
					term := false
					switch {
					case raw[j] == 0x07: // BEL 终止，吃掉 BEL
						j++
						term = true
					case raw[j] == 0x1b: // ESC：可能是 ST 的前导
						if j+1 < n && raw[j+1] == '\\' {
							j += 2 // 吃掉 ST: ESC \
						} else {
							j++ // 孤立 ESC，消费到 ESC 为止
						}
						term = true
					default:
						j++
					}
					if term {
						break
					}
				}
				i = j
				continue
			default:
				// ESC + 单字节（如 ESC M 反卷、ESC 7 存光标）：两字节一起丢。
				i += 2
				continue
			}
		case c == 0x1b:
			// 末尾孤立 ESC：丢弃。
			i++
			continue
		case c < 0x20 || c == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
		i++
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
