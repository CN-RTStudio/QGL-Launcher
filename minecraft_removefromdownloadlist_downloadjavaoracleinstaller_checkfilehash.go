package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"strings"

)

func (a *App) checkFileHash(filePath string, expectedSHA1 string) bool {
	info, err := os.Stat(filePath)
	if err != nil || info.Size() == 0 {
		return false
	}

	if expectedSHA1 == "" {
		return true // 无 SHA1 要求，文件存在即可
	}

	// 计算 SHA1
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}

	actualSHA1 := fmt.Sprintf("%x", h.Sum(nil))
	return strings.EqualFold(actualSHA1, expectedSHA1)
}

// getMirrorURLs 获取多个镜像下载 URL（参考 PCL 的多源下载策略）
// 返回的 URL 列表按优先级排列：镜像源优先，官方源作为备用
