package main

import (
	_ "embed"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) GetFullLog() string {
	if a.launchLogPath != "" {
		if data, err := os.ReadFile(a.launchLogPath); err == nil && len(data) > 0 {
			return string(data)
		}
	}
	mcDir := a.GetMinecraftDir()
	if data, err := os.ReadFile(filepath.Join(mcDir, "qgl_install.log")); err == nil {
		return string(data)
	}
	return "暂无日志"
}

// ExportLogTxt 弹出保存对话框，将完整日志导出为 txt，返回保存路径（取消返回空）
func (a *App) ExportLogTxt() string {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "导出日志",
		DefaultFilename: "QGL日志.txt",
		Filters: []runtime.FileFilter{
			{DisplayName: "文本文件 (*.txt)", Pattern: "*.txt"},
		},
	})
	if err != nil || path == "" {
		return ""
	}
	if err := os.WriteFile(path, []byte(a.GetFullLog()), 0644); err != nil {
		return ""
	}
	return path
}

// ViewFullLog 用记事本打开完整日志
