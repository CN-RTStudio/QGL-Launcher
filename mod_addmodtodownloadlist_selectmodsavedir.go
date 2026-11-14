package main

import (

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) SelectModSaveDir() (string, error) {
	path, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 Mod 保存位置",
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// GetDefaultModDir 获取默认 Mod 目录
