package main

import (
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
