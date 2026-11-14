package main

import (
	"errors"
	"io"
)

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
