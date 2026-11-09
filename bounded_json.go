package main

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

var (
	errJSONFetchTooLarge     = errors.New("JSON 响应体积超过安全上限")
	errJSONFetchBadType      = errors.New("JSON 响应 Content-Type 不被允许")
	errJSONFetchNoLimit      = errors.New("拉取 JSON 必须指定正的体积上限")
	errJSONFetchNoSuccessful = errors.New("全部 JSON 源地址都获取失败")

	// jsonFetchBackoffBase 是 5xx 重试的基础退避；设为变量而非常量，便于测试缩短等待。
	jsonFetchBackoffBase = 500 * time.Millisecond
)

const (
	jsonFetchDefaultAttempts = 3
	jsonFetchBufSize         = 64 * 1024
	jsonFetchMaxContentType  = 256

	// jsonLocalDefaultMaxBytes 是“本地版本/资产 JSON”读取的默认体积上限（64MiB）。
	// 正常版本 JSON（含 Forge 这类带大量库条目的）也就几 MiB，给 64MiB 是刻意取宽，
	// 只拦被恶意塞成 GB 级、会把进程内存打爆的“json”文件（炸磁盘/内存才拦）。
	jsonLocalDefaultMaxBytes int64 = 64 << 20
)

// jsonFetchOptions 控制一次有界 JSON 拉取。
type jsonFetchOptions struct {
	MaxBytes        int64        // 必填：响应体硬上限，超出即 fatal
	Attempts        int          // 可空：<=0 取 jsonFetchDefaultAttempts
	UserAgent       string       // 可空：为空不覆盖 UA
	Client          *http.Client // 可空：为空用 safeHTTPClient()
	AllowMediaTypes []string     // 可空：非空时响应媒体类型必须命中其一（小写比较）
	SourceLabel     string       // 可空：审计日志中标识这份元数据的名字，如 "版本清单"
}

// parseMediaType 从 Content-Type 头取 media type（去掉 ;charset=...），
// 并对异常超长头做收口，防止审计日志被撑大。
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
