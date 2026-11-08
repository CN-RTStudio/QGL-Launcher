package main

// serverfaviconguard.go —— 服务器列表 ping 回来的 favicon URL 校验。
//
// MC 服务器列表 ping 响应里带一个 favicon 字段（data:image/png;base64 或
// 一个 URL）。如果允许 URL 形式，启动器去抓它就等于对内网/任意主机发请求
// （SSRF），还会把用户 IP 暴露给恶意服务器。这里把"这个 favicon 该不该被
// 启动器请求/接受"收敛成纯函数。

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// maxServerFaviconBytes 内联 favicon 的硬上限。
const maxServerFaviconBytes = 1024 * 64

const maxServerFaviconEncoded = maxServerFaviconBytes*4/3 + 16

func faviconHostOnly(raw string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(raw))
	if h == "" {
		return "", false
	}
	if strings.ContainsAny(h, " \t\r\n\"'<>`%/@?#\\") {
		return "", false
	}
	h = strings.Trim(h, "[]")
	h = strings.TrimRight(h, ".")
	if h == "" || strings.Contains(h, "..") {
		return "", false
	}
	if net.ParseIP(h) != nil {
		return "", false
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return "", false
	}
	if !strings.Contains(h, ".") {
		return "", false
	}
	last := h[strings.LastIndex(h, ".")+1:]
	digitsOnly := len(last) > 0
	for i := 0; i < len(last); i++ {
		c := last[i]
		if c < '0' || c > '9' {
			digitsOnly = false
			break
		}
	}
	if digitsOnly {
		return "", false
	}
	return h, true
}

// ValidateServerFavicon 校验 favicon 字段。
// 只接受 data:image/png;base64 形式；其他一律拒绝。
// 返回 (cleanedBase64, error)。
func ValidateServerFavicon(field string) (string, error) {
	f := strings.TrimSpace(field)
	if f == "" {
		return "", nil
	}
	if !strings.HasPrefix(f, "data:image/png;base64,") {
		return "", fmt.Errorf("favicon must be data:image/png;base64")
	}
	raw := strings.TrimSpace(strings.TrimPrefix(f, "data:image/png;base64,"))
	if len(raw) > maxServerFaviconEncoded {
		return "", fmt.Errorf("favicon payload too long: %d chars", len(raw))
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("favicon base64: %w", err)
	}
	if len(decoded) == 0 {
		return "", fmt.Errorf("empty favicon payload")
	}
	if len(decoded) > maxServerFaviconBytes {
		return "", fmt.Errorf("favicon too large: %d bytes", len(decoded))
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

// ValidateServerFaviconURL 校验外部 favicon URL（未来若支持）。
// 仅允许 https，且不允许内网/回环主机。
func ValidateServerFaviconURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("empty favicon url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("bad favicon url: %w", err)
	}
	if u.Opaque != "" {
		return fmt.Errorf("opaque favicon url")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("favicon url must be https")
	}
	if u.User != nil {
		return fmt.Errorf("favicon url must not carry userinfo")
	}
	host, ok := faviconHostOnly(u.Hostname())
	if !ok {
		return fmt.Errorf("bad favicon host")
	}
	if isLoopbackOrPrivateHost(host) {
		return fmt.Errorf("favicon host is private: %s", host)
	}
	return nil
}
