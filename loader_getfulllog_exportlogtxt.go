package main

import (
	_ "embed"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

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
