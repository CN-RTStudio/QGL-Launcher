package main

import (
	"net/url"
	"os"
	"path/filepath"
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
func hasASCIIWhitespaceOrControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// MaxFileSize 返回文件大小是否在安全上限内。
// limitBytes <= 0 时用默认 2 GiB。
func MaxFileSize(p string, limitBytes int64) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	if limitBytes <= 0 {
		limitBytes = maxDownloadBytes
	}
	return info.Size() >= 0 && info.Size() <= limitBytes
}

// PathWithin 返回 clean 后的路径，并校验它没有跳出 root。
// 返回 ("", false) 表示路径穿越 / 不存在 / 是符号链接指向外面。
//
// 用法：
//
//	rel, ok := PathWithin("/opt/mc/versions", userSuppliedPath)
//
// 调用方拿到 rel 后再 Join(root, rel) 拼最终绝对路径，绝不直接用 userSuppliedPath。
//
// 安全说明：光做 filepath.Rel 的词法判定挡不住符号链接 / junction——
// root 内若被预先放进一个指向外部目录的链接，词法上路径仍“在 root 里”，
// 实际读写却落到 root 外。这里在词法检查之外再做一次真实路径解析（见
// resolvedInside），任何一段把目标带到 root 之外的链接都判为越界。
func PathWithin(root string, p string) (string, bool) {
	if p == "" {
		return "", false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(rootAbs, abs)
	if err != nil {
		return "", false
	}
	if rel == "." {
		// 即使目标就是 root 本身，也要确认 root 没被链接到别处。
		if !resolvedInside(rootAbs, abs) {
			return "", false
		}
		return ".", true
	}
	// 词法在 root 内，再确认解析所有符号链接后仍在 root 内。
	// 旧实现用 strings.HasPrefix(rel, "..")，会把 root 内合法的 "..keep" 条目
	// 误判成越界；改由 lexicallyWithin 精确比较 ".." 与 ".."+分隔符。
	if !lexicallyWithin(rootAbs, abs) {
		return "", false
	}
	if !resolvedInside(rootAbs, abs) {
		return "", false
	}
	return rel, true
}

// lexicallyWithin 判断 target 的词法绝对路径是否落在 root 内（不跟随链接）。
func lexicallyWithin(rootAbs, targetAbs string) bool {
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." &&
		!strings.HasPrefix(rel, ".."+string(os.PathSeparator)) &&
		!filepath.IsAbs(rel)
}

// resolvedInside 在解析符号链接 / junction 后判断 p 是否仍位于 root 内。
// p 已存在时直接 EvalSymlinks；p 尚不存在（典型的“准备创建的目标文件”）时，
// 向上找到第一个真实存在的祖先目录，解析它后再接回尚未存在的相对后缀，
// 防止攻击者用“root 内一个指向外部的已存在链接 + 尚不存在的文件名”绕过检查。
