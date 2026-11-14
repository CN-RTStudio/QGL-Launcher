package main

import (
	"net/url"
	"strconv"
	"strings"
)

func ValidateModName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// ValidateURL 只允许 http/https，且长度 <= 2048（Go url.Parse 不会替你挡超长串）。
// 旧实现只比对前缀字符串，`https://`（无主机）、`https://user:pw@host/x`（userinfo
// 夹带凭据）、`https://example.com/a b.jpg`（空格）、含 NUL 的串都会判为合法，
// 调用方（user.go 的壁纸 Location 校验）随后直接拿去发请求。这里改成真正解析：
// 协议白名单 + 必须有主机 + 拒绝 userinfo + 拒绝空白/控制字节 + 端口范围校验。
func ValidateURL(raw string) bool {
	if raw == "" || len(raw) > 2048 {
		return false
	}
	if hasASCIIWhitespaceOrControl(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return false
	}
	// Opaque（如 `http:foo`）没有 host 语义；Host/Hostname 为空同样拒绝。
	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return false
	}
	if u.User != nil {
		return false
	}
	if port := u.Port(); port != "" {
		n, convErr := strconv.Atoi(port)
		if convErr != nil || n <= 0 || n > 65535 {
			return false
		}
	}
	return true
}

// hasASCIIWhitespaceOrControl 报告串里是否有空格 / 制表 / C0 控制字节 / DEL。
// 这些字节进不了合法 URL，但 url.Parse 对空格是宽容的，必须显式拦下。
