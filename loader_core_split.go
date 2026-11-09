package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func isSafeRelPath(relPath string) string {
	if relPath == "" {
		return ""
	}
	cleaned := filepath.Clean(relPath)
	// 拒绝绝对路径
	if filepath.IsAbs(cleaned) {
		return ""
	}
	// 拒绝以 .. 开头的逃逸路径
	if strings.HasPrefix(cleaned, "..") {
		return ""
	}
	// 拒绝包含 .. 段的路径
	parts := strings.Split(cleaned, string(os.PathSeparator))
	for _, p := range parts {
		if p == ".." {
			return ""
		}
	}
	return cleaned
}
func (a *App) writeLog(format string, args ...interface{}) {
	// 在写控制台 / qgl_install.log / 启动日志之前统一脱敏：启动参数与游戏输出里
	// 可能带微软 access token、Bearer、JWT、密码等，任何一处落盘/外发都算泄密。
	msg := sanitizeLogLine(fmt.Sprintf(format, args...))
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, msg)

	fmt.Print(logLine)

	mcDir := a.GetMinecraftDir()
	logPath := filepath.Join(mcDir, "qgl_install.log")
	// 有界日志：4MiB 软上限 + 单份 .1 轮转 + 拒符号链接，防止崩溃循环刷屏占满磁盘。
	_ = getBoundedLogger(logPath).appendBounded(logLine)

	if a.launchLogPath != "" {
		dir := filepath.Dir(a.launchLogPath)
		// 日志目录同样收权到 0700（已存在的宽权限目录一并收敛），失败则放弃本次日志落盘。
		if ensurePrivateDir(dir) == nil {
			_ = getBoundedLogger(a.launchLogPath).appendBounded(logLine)
		}
	}
}
