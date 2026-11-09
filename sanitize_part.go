package main

import (
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

func resolvedInside(rootAbs, p string) bool {
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		rootReal = rootAbs // root 尚不存在时退化为词法根
	}
	rootReal, _ = filepath.Abs(rootReal)

	if real, err := filepath.EvalSymlinks(p); err == nil {
		return lexicallyWithin(rootReal, real)
	}

	// p（或其某一级祖先）不存在：定位最长的已存在祖先。
	existing := p
	for {
		if _, statErr := os.Lstat(existing); statErr == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break // 已到卷根，无法再向上
		}
		existing = parent
	}

	realExisting, err := filepath.EvalSymlinks(existing)
	if err != nil {
		realExisting = existing
	}
	suffix, err := filepath.Rel(existing, p)
	if err != nil {
		return false
	}
	rebuilt, err := filepath.Abs(filepath.Join(realExisting, suffix))
	if err != nil {
		return false
	}
	return lexicallyWithin(rootReal, rebuilt)
}

// IsSymlink 报告给定路径是否是符号链接本身（不跟随）。
func IsSymlink(p string) bool {
	info, err := os.Lstat(p)
	if err != nil {
		return false
	}
	return info.Mode()&fs.ModeSymlink != 0
}

// SafeJoin 在 root 下拼一个相对子路径，任何一步越界都返回 false。
// 用于 renderer 传 "versions/1.20/mods" 这种相对路径时，确保它真的在 root 里。
func SafeJoin(root string, rel string) (string, bool) {
	if root == "" || rel == "" {
		return "", false
	}
	// 绝对路径 / 盘符 / UNC：filepath.Join 会把它们当成“已绝对”直接吞掉 root。
	// Windows 下 "/abs/x" 不算 IsAbs（只是“当前盘根”），但它表达的是绝对意图，
	// 静默改成 root\abs\x 会让调用方写错位置，这里一并拒绝。
	if filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" ||
		strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) {
		return "", false
	}
	// 旧实现先拼成 "/"+rel 再 Clean，在 Windows 上 Clean("/") 返回反斜杠根，
	// TrimPrefix 剥不掉，导致 ""/"."/".." 被拼成 root 本身并放行；同时 "../x"
	// 被归一化成 "x" 静默落到 root 内另一个文件，调用方以为写的是别处。
	// 这里改成逐段白名单式拼接：任何 ".." 段直接拒绝，不做“归一化吞掉”。
	segs := strings.Split(strings.ReplaceAll(rel, `\`, "/"), "/")
	parts := make([]string, 0, len(segs)+1)
	parts = append(parts, root)
	for _, seg := range segs {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			return "", false
		}
		parts = append(parts, seg)
	}
	if len(parts) == 1 {
		return "", false
	}
	full := filepath.Join(parts...)
	if _, ok := PathWithin(root, full); !ok {
		return "", false
	}
	return full, true
}

// SanitizeFilename 把用户输入的文件名里危险字符替换掉，避免路径分隔符 / 保留名。
// 不做空判断（空串由调用方决定怎么处理）。
func SanitizeFilename(name string) string {
	if name == "" {
		return name
	}
	// Windows 保留字符
	for _, c := range []string{`<`, `>`, `:`, `"`, `/`, `\`, `|`, `?`, `*`} {
		name = strings.ReplaceAll(name, c, "_")
	}
	// 不可见空白（U+00A0 不换行空格、U+2000–U+200A 各种窄空格、U+202F、
	// U+205F、U+3000 表意空格、U+1680 欧甘空格）在资源管理器里和普通空格几乎
	// 无法区分，下面的 TrimLeft/TrimRight(" .") 又不会处理它们：名字尾部留一个
	// U+00A0 时磁盘上实际是 `x .jar`，审计日志里看到的却是 `x .jar`，可用来做
	// 扩展名视觉混淆。统一换成下划线，保证审计名与实际落盘名逐字节一致。
	name = strings.Map(func(r rune) rune {
		if r == '\u00A0' || r == '\u1680' || r == '\u202F' || r == '\u205F' || r == '\u3000' || (r >= '\u2000' && r <= '\u200A') {
			return '_'
		}
		return r
	}, name)
	// 去掉首尾空格和点（Windows 不允许文件名以点结尾）
	name = strings.TrimLeft(name, " .")
	name = strings.TrimRight(name, " .")
	name = truncateFilenameBytes(name, 128)
	// 截断可能重新落在点/空格上，再剥一次，保证审计名与磁盘名一致。
	name = strings.TrimRight(name, " .")
	if name == "" {
		return name
	}
	// Windows 保留设备名（CON / PRN / AUX / NUL / COM1..9 / LPT1..9）带扩展名也会
	// 落到设备上（CON.txt 仍写进控制台），加下划线前缀让它变成普通文件。
	// 原实现只替换非法字符，保留名会原样放行，写入会失败或丢数据。
	if isReservedDeviceName(stemOfName(name)) {
		name = "_" + name
	}
	return name
}

// truncateFilenameBytes 把文件名截到 max 字节，并回退到合法 UTF-8 边界。
// 直接切字节会把多字节字符劈成半个，Windows 落盘会直接拒绝该名字。
func truncateFilenameBytes(name string, max int) string {
	if max <= 0 || len(name) <= max {
		return name
	}
	cut := name[:max]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// ValidateModName 校验 mod / 版本 ID 是否合法：
// 只允许字母数字、点、下划线、短横线，长度 1~64。
// 这是 Minecraft 版本目录、mod 文件名的实际约定。
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
