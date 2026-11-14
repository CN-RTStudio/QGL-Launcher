package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

)

func (a *App) downloadJavaOracleInstaller(majorVer int, url string) error {
	javaList := a.GetJavaDownloadList()
	var target *JavaDownloadInfo
	for i := range javaList {
		if javaList[i].MajorVer == majorVer {
			target = &javaList[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("未找到 Java %d 的下载信息", majorVer)
	}

	// 如果是网页链接（回退方案），用系统默认浏览器打开 Oracle 官方下载页
	if target.IsWebPage {
		webURL := target.URL
		if webURL == "" {
			webURL = url
		}
		cmd := exec.Command("cmd", "/c", "start", webURL)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Run()
	}

	// 下载到 %temp%
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	destPath := filepath.Join(tempDir, target.FileName)

	// 如果文件已存在，直接运行
	if _, err := os.Stat(destPath); err == nil {
		return runInstaller(destPath, target.IsMSI)
	}

	// 多线程分段下载安装包
	a.emitProgress("downloading", target.FileName, 0, 0)
	if err := a.downloadFileMultiThread(url, destPath, 8); err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}

	// 下载完成，运行安装程序
	return runInstaller(destPath, target.IsMSI)
}

// runInstaller 运行安装程序
