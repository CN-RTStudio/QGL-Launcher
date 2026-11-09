package main

// httpdiag.go —— HTTP 非成功响应的“诊断摘要”读取内核。
//
// 历史上 mod.go / modpack.go 在收到非 2xx 响应时各自手写：
//
//	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
//	return nil, fmt.Errorf("... HTTP %d, %s", resp.StatusCode, string(body))
//
//	这有两个真实问题：
//
//	 1. 吞掉读体错误（body, _）：连接在返回错误页途中被重置时，半截内容会被当成
//	    完整的服务端消息展示与记录；
//	 2. 把原始响应体直接拼进 error（该 error 会进入 writeLog、前端弹窗与安全审计）：
//	    被劫持的镜像可在错误体里塞 CR/LF 伪造日志与审计行（日志注入）、塞 NUL 或
//	    终端转义序列（ESC[31m / ESC]0;...）干扰控制台，或灌一大段无空白文本撑爆单条记录。
//
// readResponseSnippet 有界读取一段响应体，并净化成“可安全写日志/展示”的单行摘要；
// httpStatusError 把状态码与净化后的摘要组合成统一错误。

import (
	"errors"
	"fmt"
	"io"
	"net/http"
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

// readResponseSnippet 从 rc 最多读取 limit 字节作为诊断摘要，并净化为安全单行文本。
//
//   - limit<=0 时取 httpDiagDefaultSnippetBytes；超过 httpDiagMaxSnippetBytes 时收敛到该值；
//   - 多读 1 字节判定原始响应是否更长，truncated=true 表示摘要被截断；
//   - 读体中断（连接重置等）如实返回非 EOF 错误，同时仍带回已读到（并已净化）的前缀，
//     是否采用该前缀由调用方决定；
//   - 返回的 snippet 绝不含控制字符，可安全拼进 error / 日志 / 审计。
func readResponseSnippet(rc io.Reader, limit int) (snippet string, truncated bool, err error) {
	if limit <= 0 {
		limit = httpDiagDefaultSnippetBytes
	}
	if limit > httpDiagMaxSnippetBytes {
		limit = httpDiagMaxSnippetBytes
	}
	raw, readErr := io.ReadAll(io.LimitReader(rc, int64(limit)+1))
	if len(raw) > limit {
		truncated = true
		raw = raw[:limit]
	}
	snippet = sanitizeSnippet(raw)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return snippet, truncated, readErr
	}
	return snippet, truncated, nil
}

// formatHTTPStatusError 组合状态码与净化摘要为错误信息（纯函数，便于单测）。
// snippet 为空时只返回状态码；truncated 时追加省略号提示摘要被截断。
func formatHTTPStatusError(statusCode int, snippet string, truncated bool, context string) error {
	msg := fmt.Sprintf("%s: HTTP %d", context, statusCode)
	if snippet != "" {
		msg += ", " + snippet
		if truncated {
			msg += "…"
		}
	}
	return errors.New(msg)
}

// httpStatusError 读取 resp.Body 的诊断摘要并生成错误。
//
// 此处刻意不把“读取摘要失败”升级为返回错误：HTTP 非 2xx 的状态码本身已经是主错误，
// 摘要仅用于辅助诊断；即便摘要是在连接中断中读到的前缀，也已剥除全部控制字符，
// 拼进日志是安全的。调用方应在错误分支调用，并自行保证 resp.Body 最终被关闭。
func httpStatusError(resp *http.Response, context string) error {
	snippet, truncated, _ := readResponseSnippet(resp.Body, httpDiagDefaultSnippetBytes)
	return formatHTTPStatusError(resp.StatusCode, snippet, truncated, context)
}
