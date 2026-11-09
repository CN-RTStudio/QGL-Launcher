package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

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
