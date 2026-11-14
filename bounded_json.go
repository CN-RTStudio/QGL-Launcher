package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func readLocalJSONBounded(path string, out any, maxBytes int64, label string) error {
	if maxBytes <= 0 {
		maxBytes = jsonLocalDefaultMaxBytes
	}
	if label == "" {
		label = "本地 JSON"
	}

	// 复用全仓唯一的本地有界读取原语：stat 声明拦截 + LimitReader+1 兜底 +
	// 符号链接/特殊文件拒绝，超限返回 errLocalFileTooLarge。
	body, err := readBoundedFile(path, maxBytes)
	if err != nil {
		if errors.Is(err, errLocalFileTooLarge) {
			recordSecurityEvent("local-json", auditSeverityCritical, auditActionBlocked,
				"bounded-json", fmt.Sprintf("%s实际体积超过上限 %d: %s", label, maxBytes, path))
		}
		return err
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("解析%s失败: %w", label, err)
	}
	return nil
}

func fetchJSONFromMirrors(ctx context.Context, urls []string, out any, opts jsonFetchOptions) error {
	var lastErr error
	for _, u := range urls {
		if err := fetchJSONBounded(ctx, u, out, opts); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errJSONFetchNoSuccessful
	}
	return fmt.Errorf("%w: %v", errJSONFetchNoSuccessful, lastErr)
}

// fetchJSONBounded 拉取单个 HTTPS URL 上的 JSON 并反序列化到 out。
// 网络错误 / 408 / 429 / 5xx / 读体中断按指数退避重试；协议错误、超限、
// 媒体类型不符、JSON 语法错误为 fatal 不重试。
