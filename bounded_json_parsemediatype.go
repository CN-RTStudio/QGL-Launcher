package main

import (
	"io"
	"strings"
)

func parseMediaType(header string) string {
	h := strings.TrimSpace(header)
	if len(h) > jsonFetchMaxContentType {
		h = h[:jsonFetchMaxContentType]
	}
	if i := strings.IndexByte(h, ';'); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

// mediaTypeAllowed 判断实际媒体类型是否命中白名单。白名单为空表示不校验。
func mediaTypeAllowed(actual string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, m := range allow {
		if actual == strings.ToLower(strings.TrimSpace(m)) {
			return true
		}
	}
	return false
}

// readBoundedBody 从 rc 最多读取 maxBytes+1 字节。
// 返回 errJSONFetchTooLarge 表示实际数据超过上限；调用方不得使用 data。
func readBoundedBody(rc io.Reader, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(rc, maxBytes+1)
	buf := make([]byte, 0, 256)
	chunk := make([]byte, jsonFetchBufSize)
	for {
		n, err := limited.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if int64(len(buf)) > maxBytes {
				return nil, errJSONFetchTooLarge
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}
