package main

// launchernewsguard.go —— 启动器内置新闻/公告拉取地址白名单。
//
// 启动器首屏会拉一条“新闻/公告”JSON。如果这个地址被配置成任意 URL，就能
// 被用来对内网发请求（SSRF），或在 http 明文通道里窃听/篡改内容。这里把
// “这个新闻地址该不该被启动器请求”收敛成纯函数。

import (
	"fmt"
	"net/url"
	"strings"
)

// 允许的新闻源主机后缀。
var allowedNewsHostSuffixes = []string{
	".minecraft.net",
	".mojang.com",
}

// ValidateNewsFeedURL 校验新闻源 URL。
// extraAllowed 是用户在配置里显式放行的自定义主机。
func ValidateNewsFeedURL(raw string, extraAllowed []string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("empty news url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("bad news url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("news feed must be https, got %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("empty news host")
	}
	for _, suf := range allowedNewsHostSuffixes {
		if host == strings.TrimPrefix(suf, ".") || strings.HasSuffix(host, suf) {
			return nil
		}
	}
	for _, a := range extraAllowed {
		if strings.EqualFold(host, strings.TrimSpace(a)) {
			return nil
		}
	}
	return fmt.Errorf("news host not allowed: %s", host)
}

// IsAllowedNewsFeed 便捷布尔入口。
func IsAllowedNewsFeed(raw string, extra []string) bool {
	return ValidateNewsFeedURL(raw, extra) == nil
}
