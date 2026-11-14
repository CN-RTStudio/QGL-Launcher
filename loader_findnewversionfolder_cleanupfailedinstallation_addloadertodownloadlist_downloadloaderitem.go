package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

)

func (a *App) downloadLoaderItem(item *DownloadItem) error {
	if item.URL == "" {
		return fmt.Errorf("下载地址为空")
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	fileName := item.CustomName
	if strings.HasSuffix(strings.ToLower(item.URL), ".jar") {
		if !strings.HasSuffix(strings.ToLower(fileName), ".jar") {
			fileName += ".jar"
		}
	} else if strings.HasSuffix(strings.ToLower(item.URL), ".exe") {
		if !strings.HasSuffix(strings.ToLower(fileName), ".exe") {
			fileName += ".exe"
		}
	}

	destPath := filepath.Join(tempDir, fileName)

	a.emitProgress("downloading", fileName, 0, 0)

	if err := a.downloadFile(item.URL, destPath, true); err != nil {
		return fmt.Errorf("下载加载器失败: %v", err)
	}

	// 如果是 JAR 安装器，自动运行
	if strings.HasSuffix(strings.ToLower(destPath), ".jar") {
		javaEntry := a.SearchJava()
		if len(javaEntry) == 0 {
			return fmt.Errorf("下载完成但未找到 Java 来运行安装器，请手动运行: %s", destPath)
		}
		cmd := exec.Command(javaEntry[0].Path, "-jar", destPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("启动安装器失败: %v", err)
		}
	}

	return nil
}
