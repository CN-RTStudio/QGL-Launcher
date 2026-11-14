package main

import (
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) SelectBackgroundImage() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择背景图片",
		Filters: []runtime.FileFilter{
			{DisplayName: "图片文件", Pattern: "*.jpg;*.jpeg;*.png;*.bmp;*.webp"},
		},
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// GetBackgroundImageDataURL 获取背景图片的 base64 Data URL（用于 CSS background-image）
func (a *App) GetBackgroundImageDataURL() string {
	path := a.GetBackgroundImage()
	if path == "" || !fileExists(path) {
		return ""
	}
	url, err := a.fileToDataURL(path)
	if err != nil {
		return ""
	}
	return url
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetBingDailyImage 获取 Bing 每日壁纸图片
// 1. 请求 Bing API 获取重定向 URL
// 2. 跟随重定向获取实际图片
// 3. 缓存到本地并返回 data URL
