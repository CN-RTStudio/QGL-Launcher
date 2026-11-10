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

// 本文件集中放置跨模块复用的输入/路径校验工具。
// 之前 user.go / modpack.go / loader.go 各自手写一遍"在不在某个根目录下"，
// 逻辑重复且容易漏 case，抽出来后所有 renderer 传入的路径都过同一套检查。

// maxDownloadBytes 单次下载最大体积 2 GiB，防恶意 CDN / mod repo 塞多 G 文件。
const maxDownloadBytes = 2 << 30

// safeImageExts 允许作为背景图/头像/缩略图的扩展名。
var safeImageExts = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".bmp":  true,
	".webp": true,
}

// safeArchiveExts 允许用户导入的压缩包类型（modpack / resourcepack）。
var safeArchiveExts = map[string]bool{
	".zip":    true,
	".mrpack": true, // Modrinth modpack
}

// IsSafeImageExt 判断扩展名是否是受支持的图片类型。
func IsSafeImageExt(path string) bool {
	return safeImageExts[strings.ToLower(filepath.Ext(path))]
}

// IsSafeArchiveExt 判断扩展名是否是受支持的压缩包类型。
func IsSafeArchiveExt(path string) bool {
	return safeArchiveExts[strings.ToLower(filepath.Ext(path))]
}

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
