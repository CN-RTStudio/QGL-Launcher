package main

import (
	"os"
	"path/filepath"
	"strings"
)

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
