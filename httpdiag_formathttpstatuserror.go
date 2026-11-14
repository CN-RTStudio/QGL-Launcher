package main

import (
	"errors"
	"fmt"
	"net/http"
)

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
