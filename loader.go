package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ===== 日志功能 =====

// writeLog 将信息写入日志文件（用户可随时查看和复制）
func (a *App) writeLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, msg)

	// 打印到控制台
	fmt.Print(logLine)

	// 写入安装日志（.minecraft 根目录）
	mcDir := a.GetMinecraftDir()
	logPath := filepath.Join(mcDir, "qgl_install.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		f.WriteString(logLine)
		f.Close()
	}

	// 写入启动日志（版本目录下的 QGL\Logs，与 UI 报错内容一致）
	if a.launchLogPath != "" {
		dir := filepath.Dir(a.launchLogPath)
		os.MkdirAll(dir, 0755)
		f2, err2 := os.OpenFile(a.launchLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err2 == nil {
			f2.WriteString(logLine)
			f2.Close()
		}
	}
}

// GetFullLog 获取完整日志文本（优先本次启动日志，其次安装日志）
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
