package main

import (

)

func (a *App) GetDownloadProgress() DownloadProgress {
	return a.downloadProgress
}

// isVersionIsolated 检查是否启用版本隔离
