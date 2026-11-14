package main

import (

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) SelectPclExe() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 PCL 启动器的可执行文件",
		Filters: []runtime.FileFilter{
			{DisplayName: "PCL 启动器", Pattern: "*.exe"},
		},
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// SelectMinecraftDir 弹出文件夹选择框选择 .minecraft 目录
