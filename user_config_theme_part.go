package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"os"
)

// SetBackgroundImage 设置当前用户的背景图片路径
func (a *App) SetBackgroundImage(path string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	// 安全加固：不接受任意路径，只能是 Pictures/Videos 或 QGL/cache 下的图片
	if !a.isSafeBackgroundPath(path) {
		return fmt.Errorf("背景图片路径不安全或不在允许目录内")
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.BackgroundImage = path
	err = a.SaveUserConfig(currentUser.Username, config)
	if err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "backgroundChanged", path)
	return nil
}

// SelectBackgroundImage 打开文件选择对话框选择背景图片
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
	// 安全加固：即使 config 里残留了老路径，读之前再校一遍
	if !a.isSafeBackgroundPath(path) {
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
