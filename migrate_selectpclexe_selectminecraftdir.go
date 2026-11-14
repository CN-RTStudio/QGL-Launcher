package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
func (a *App) GetPclCEMcDir() (string, error) {
	// 1) PCL CE 本地配置
	cfgPath := filepath.Join(os.Getenv("APPDATA"), ".PCLCE", "Config.json")
	if data, err := os.ReadFile(cfgPath); err == nil {
		var m map[string]interface{}
		if json.Unmarshal(data, &m) == nil {
			if v, ok := m["LaunchFolders"]; ok {
				// 格式: "pclce>D:\pclce\.minecraft\"，取 > 后面的路径
				raw := strings.TrimSpace(fmt.Sprint(v))
				if idx := strings.Index(raw, ">"); idx >= 0 {
					raw = strings.TrimSpace(raw[idx+1:])
				}
				if raw != "" {
					// 去掉末尾的反斜杠/斜杠
					raw = strings.TrimRight(raw, `/\`)
					if info, err := os.Stat(raw); err == nil && info.IsDir() {
						return raw, nil
					}
				}
			}
		}
	}

	// 2) 常见位置搜索，取第一个 .minecraft
	results, _ := a.SearchMinecraftFolders()
	if len(results) > 0 {
		return results[0].Path, nil
	}

	return "", fmt.Errorf("未能自动获取游戏目录，请手动选择 .minecraft 文件夹")
}

// GetPclMcDir 从 PCL 的配置中读取游戏目录
// PCL 配置位于 PCL.exe 所在目录的 PCL\Setup.ini，格式为无 section 的 key:value 行
// 只取 LaunchFolderSelect（游戏目录）
