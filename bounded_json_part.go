package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// fetchJSONBounded 拉取单个 HTTPS URL 上的 JSON 并反序列化到 out。
// 网络错误 / 408 / 429 / 5xx / 读体中断按指数退避重试；协议错误、超限、
// 媒体类型不符、JSON 语法错误为 fatal 不重试。
func fetchJSONBounded(ctx context.Context, rawURL string, out any, opts jsonFetchOptions) error {
	if !isHTTPSURL(rawURL) {
		return fmt.Errorf("拒绝不安全的 JSON URL（非 HTTPS）: %s", rawURL)
	}
	if opts.MaxBytes <= 0 {
		return errJSONFetchNoLimit
	}
	attempts := opts.Attempts
	if attempts <= 0 {
		attempts = jsonFetchDefaultAttempts
	}
	client := opts.Client
	if client == nil {
		client = safeHTTPClient()
	}
	label := opts.SourceLabel
	if label == "" {
		label = "JSON 元数据"
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		fatal, err := attemptJSONFetch(ctx, client, rawURL, out, opts, label)
		if err == nil {
			return nil
		}
		lastErr = err
		if fatal || attempt == attempts {
			return err
		}
		backoff := jsonFetchBackoffBase << uint(attempt-1)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return lastErr
}

// attemptJSONFetch 是单次尝试。
func attemptJSONFetch(ctx context.Context, client *http.Client, rawURL string,
	out any, opts jsonFetchOptions, label string) (fatal bool, err error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return true, fmt.Errorf("创建请求失败 %s: %w", rawURL, err)
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// DNS / 连接重置 / 超时属于瞬时错误。
		return false, fmt.Errorf("%s请求失败 %s: %w", label, rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusRequestTimeout ||
			resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode >= 500
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"bounded-json", fmt.Sprintf("%s源返回 HTTP %d: %s", label, resp.StatusCode, rawURL))
		if !retryable {
			return true, fmt.Errorf("%w: HTTP %d (%s)", errSecureDownloadStatus, resp.StatusCode, rawURL)
		}
		return false, fmt.Errorf("%w: HTTP %d (%s)", errSecureDownloadStatus, resp.StatusCode, rawURL)
	}

	// 声明体积超限：连 body 都不必读。
	if resp.ContentLength > opts.MaxBytes {
		recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
			"bounded-json",
			fmt.Sprintf("%s声明体积 %d 超过上限 %d: %s", label, resp.ContentLength, opts.MaxBytes, rawURL))
		return true, fmt.Errorf("%w: %s 声明 %d > %d",
			errJSONFetchTooLarge, label, resp.ContentLength, opts.MaxBytes)
	}

	media := parseMediaType(resp.Header.Get("Content-Type"))
	if media != "" && !mediaTypeAllowed(media, opts.AllowMediaTypes) {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"bounded-json",
			fmt.Sprintf("%s返回了非 JSON 媒体类型 %q: %s", label, media, rawURL))
		return true, fmt.Errorf("%w: %s 实际类型 %q", errJSONFetchBadType, label, media)
	}

	body, err := readBoundedBody(resp.Body, opts.MaxBytes)
	if err != nil {
		if errors.Is(err, errJSONFetchTooLarge) {
			recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
				"bounded-json",
				fmt.Sprintf("%s实际体积超过上限 %d: %s", label, opts.MaxBytes, rawURL))
			return true, fmt.Errorf("%w: %s 实际上限 %d", errJSONFetchTooLarge, label, opts.MaxBytes)
		}
		// 读体中断通常是瞬时网络问题，允许重试。
		return false, fmt.Errorf("读取%s响应体失败: %w", label, err)
	}

	if err := json.Unmarshal(body, out); err != nil {
		// 语法错误是服务端实际给出的内容问题，重试同一个 URL 不会变好，
		// 按 fatal 处理，让调用方尽快尝试下一个镜像。
		return true, fmt.Errorf("解析%s失败: %w", label, err)
	}
	return false, nil
}

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
