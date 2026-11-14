package main

import (

)

func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// GetDownloadProgress 获取当前下载进度
func (a *App) GetDownloadProgress() DownloadProgress {
	return a.downloadProgress
}

// isVersionIsolated 检查是否启用版本隔离
