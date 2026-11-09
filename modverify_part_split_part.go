package main

import (
	"fmt"
	"net/http"
	"os"
)

func newModDownloadClient() *http.Client {
	c := safeHTTPClient()
	c.Timeout = 0
	c.CheckRedirect = modDownloadCheckRedirect
	return c
}

// ===== 符号链接安全落盘 =====

// isSymlink 报告路径当前是否为符号链接；路径不存在时返回 false。
func isSymlink(p string) bool {
	fi, err := os.Lstat(p)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}

// openSecurePartFile 创建/截断下载临时文件。写入前用 Lstat 确认它不是
// 预置的符号链接，避免顺着链接写穿到 mods 目录之外的任意文件。
func openSecurePartFile(partPath string) (*os.File, error) {
	if isSymlink(partPath) {
		return nil, fmt.Errorf("临时文件路径是符号链接，拒绝写入: %s", partPath)
	}
	return os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
}

// finalizeDownloadFile 在完整性校验通过后把临时文件原子改名为最终文件。
// 最终路径若已被调包成符号链接同样拒绝落盘。
func finalizeDownloadFile(partPath, destPath string) error {
	if isSymlink(destPath) {
		os.Remove(partPath)
		return fmt.Errorf("目标路径是符号链接，拒绝落盘: %s", destPath)
	}
	if err := os.Rename(partPath, destPath); err != nil {
		os.Remove(partPath)
		return fmt.Errorf("重命名临时文件失败: %v", err)
	}
	return nil
}
