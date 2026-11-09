package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func (a *App) downloadJavaItem(majorVer int, url string) error {
	target, why := auditJavaDownloadRequest(majorVer, url, a.GetJavaDownloadList())
	if why != jdRejectNone {
		recordSecurityEvent(auditCategoryInstaller, auditSeverityCritical, auditActionBlocked,
			"minecraft", "Java 下载请求被拒绝: "+describeJavaDownloadReject(why))
		return fmt.Errorf("Java 下载请求被拒绝: %s", describeJavaDownloadReject(why))
	}
	if target.IsWebPage {
		// 交给系统浏览器前先过结构性校验：只允许 https 公网域名，拒绝危险 scheme、
		// userinfo 混淆、内网/本机/裸 IP 与控制字符，避免 rundll32 打开到 file:/SSRF。
		cmd, openErr := BrowserOpenCommand(url)
		if openErr != nil {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
				"minecraft", "拒绝打开不安全的 Java 下载页: "+openErr.Error())
			return fmt.Errorf("Java 下载页链接不安全: %w", openErr)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Run()
	}
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}
	if strings.ContainsAny(target.FileName, `/\\`) || strings.HasPrefix(target.FileName, `..`) {
		return fmt.Errorf(`不安全的 Java 安装文件名: %s`, target.FileName)
	}
	destPath := filepath.Join(tempDir, target.FileName)
	// %TEMP% 对同用户其它进程可写：不能看到同名文件就直接执行，否则恶意程序
	// 预先放一个同名 msi/exe 就会被我们拉起。先清掉残留（符号链接只删链接
	// 本身），本次下载的内容才是即将被校验执行的内容。发现残留本身值得审计：
	// 正常首次下载时这里应该什么都没有。
	if pre, statErr := os.Lstat(destPath); statErr == nil {
		kind := "普通文件"
		if pre.Mode()&os.ModeSymlink != 0 {
			kind = "符号链接"
		} else if !pre.Mode().IsRegular() {
			kind = "特殊文件"
		}
		recordSecurityEvent(auditCategoryInstaller, auditSeverityCritical, auditActionBlocked,
			"minecraft", "TEMP 中发现预置同名安装包("+kind+")，拒绝执行并清除: "+destPath)
	}
	if err := removeStaleInstaller(destPath); err != nil {
		return fmt.Errorf("清理旧安装包失败: %v", err)
	}
	a.emitProgress("downloading", target.FileName, 0, 0)
	ctx, cancelReq := a.downloadContext()
	defer cancelReq()
	// 安装包与普通游戏文件走同一条安全通道：HTTPS 强制、声明/实际体积双校验、
	// 临时文件流式落盘 + fsync + 原子 rename、503/网络抖动指数退避重试，
	// 失败不会在 TEMP 留半截安装包。安装包紧接着要被执行，落盘后必须补
	// Mark of the Web（ZoneId=3 Internet），让 SmartScreen 按互联网来源处置，
	// 而不是把刚下载的文件当成本机原生文件。
	opts := secureDownloadOptions{
		MaxBytes:      maxJavaInstallerBytes,
		Attempts:      3,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Client:        safeHTTPClient(),
		MarkWebOrigin: true,
		Progress: func(received, total int64) {
			a.emitProgress("downloading", target.FileName, received, total)
		},
	}
	if _, err := streamVerifiedDownload(ctx, target.URL, destPath, opts); err != nil {
		if errors.Is(err, errSecureDownloadTooLarge) {
			return fmt.Errorf("下载失败 %s: %w", target.URL, errDownloadTooLarge)
		}
		return fmt.Errorf("下载失败: %v", err)
	}
	return runInstaller(destPath, target.IsMSI)
}

func runInstaller(filePath string, isMSI bool) error {
	if err := validateInstallerPackage(filePath, isMSI); err != nil {
		recordSecurityEvent(auditCategoryInstaller, auditSeverityCritical, auditActionBlocked,
			"minecraft", "安装包执行前校验失败: "+err.Error())
		return err
	}
	if isMSI {
		cmd := exec.Command("msiexec", "/i", filePath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Start()
	}
	cmd := exec.Command("explorer", filePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}
