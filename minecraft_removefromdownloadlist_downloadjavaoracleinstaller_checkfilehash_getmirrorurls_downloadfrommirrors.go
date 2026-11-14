package main

import (
	"os"
	"path/filepath"

)

func (a *App) downloadFromMirrors(urls []string, destPath string) bool {
	for _, url := range urls {
		// 删除可能存在的损坏文件
		os.Remove(destPath)
		os.MkdirAll(filepath.Dir(destPath), 0755)

		if err := a.downloadFile(url, destPath, false); err != nil {
			a.writeLog("下载失败 [%s]: %v", url, err)
			continue
		}
		return true
	}
	return false
}

// fixAssetsIndex 补全资源文件索引（参考 PCL 的 DlClientAssetIndexGet）
