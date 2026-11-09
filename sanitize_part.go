package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
