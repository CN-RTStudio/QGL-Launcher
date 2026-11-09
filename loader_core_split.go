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

// ===== 日志功能 =====

// writeLog 将信息写入日志文件（用户可随时查看和复制）
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

// ===== 嵌入 bangbang93 ForgeInstaller =====

//go:embed resources/forge-installer.jar
var forgeInstallerJar []byte

// ===== 模组加载器相关结构体 =====

type LoaderInfo struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Version      string `json:"version"`
	MCVersion    string `json:"mcVersion"`
	DownloadURL  string `json:"downloadUrl"`
	IsInstalled  bool   `json:"isInstalled"`
	Stable       bool   `json:"stable"`
	Category     string `json:"category"`
	ForgeVersion string `json:"forgeVersion"`
	IsPreview    bool   `json:"isPreview"`
	Patch        string `json:"patch"`
	OptiFineType string `json:"optifineType"`
}

type BMCLAPIForgeEntry struct {
	Branch   string `json:"branch"`
	Modified string `json:"modified"`
	Version  string `json:"version"`
	Files    []struct {
		Category string `json:"category"`
		Format   string `json:"format"`
		Hash     string `json:"hash"`
		ID       int    `json:"id"`
		Size     int64  `json:"size"`
	} `json:"files"`
}

type BMCLAPIOptiFineEntry struct {
	MCVersion string `json:"mcversion"`
	Type      string `json:"type"`
	Patch     string `json:"patch"`
	Filename  string `json:"filename"`
	Forge     string `json:"forge"`
}

type FabricLoaderVersion struct {
	Separator string `json:"separator"`
	Build     int    `json:"build"`
	Version   string `json:"version"`
	Maven     string `json:"maven"`
	Stable    bool   `json:"stable"`
}
