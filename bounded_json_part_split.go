package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// fetchJSONFromMirrors 按顺序尝试多个镜像地址，任一成功即返回；全部失败时
// 返回 errJSONFetchNoSuccessful 并带上最后一个地址的错误。地址之间不做退避
// （它们是不同源，不是同一源的瞬时抖动），单个地址内部仍有重试。
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

// readLocalJSONBounded 从本地路径读取一份 JSON 并反序列化到 out。
//
// 与网络版共用 readBoundedBody 的“多读 1 字节”判定：实际体积严格超过 maxBytes
// 时返回 errJSONFetchTooLarge，且绝不对截断体做 Unmarshal（避免静默采用半个对象）。
// maxBytes<=0 时取 jsonLocalDefaultMaxBytes。label 仅用于安全审计标识来源。
//
// 调用方约定：文件不存在 / 内容损坏属于“跳过该缓存、回退默认逻辑”的常规分支，
// 由调用方按原语义处理；只有“体积超限”这一项在这里写安全审计，因为那通常意味着
// 本地文件被异常改写。
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
