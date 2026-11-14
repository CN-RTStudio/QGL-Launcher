package main

import (

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) SelectMinecraftDir() (string, error) {
	path, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 .minecraft 文件夹",
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// GetPclCEMcDir 自动获取 PCL CE 的游戏目录
// 读取 %APPDATA%\.PCLCE\Config.json 中的 LaunchFolders（格式 "名称>路径"），失败则搜索常见位置取第一个结果
