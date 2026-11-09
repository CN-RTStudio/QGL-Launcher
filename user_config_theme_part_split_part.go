package main

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
)

// GetCachedBingImage 获取缓存的 Bing 图片（如果存在）
func (a *App) GetCachedBingImage() string {
	cachePath := filepath.Join(a.GetQGLDir(), "cache", "bing_daily.jpg")
	if !fileExists(cachePath) {
		return ""
	}
	url, _ := a.fileToDataURL(cachePath)
	return url
}

func (a *App) fileToDataURL(path string) (string, error) {
	// 走统一的有界读取原语：stat 声明拦截 + LimitReader+1 兜底 + 拒绝符号链接/特殊文件，
	// 防止背景图被换成设备/管道或塞成超大文件把进程内存打爆。
	data, err := readBoundedFile(path, maxBackgroundDataURLBytes)
	if err != nil {
		return "", err
	}
	ext := strings.ToLower(filepath.Ext(path))
	mimeMap := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".bmp":  "image/bmp",
		".webp": "image/webp",
	}
	mimeType := mimeMap[ext]
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, b64), nil
}
