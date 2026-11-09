package main

import (
	"os"
	"path/filepath"
	"strings"
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
