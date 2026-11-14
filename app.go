package main

import (
	"context"
	"sync"
)

// App struct
type App struct {
	ctx              context.Context
	downloadProgress DownloadProgress
	downloadList     []DownloadItem
	downloadMutex    sync.Mutex
	isDownloading    bool
	downloadCancel   chan struct{}
	progressBase     float64 // 当前下载项的阶段进度映射基点（0-100）
	progressSpan     float64 // 当前下载项的阶段进度映射跨度（0 表示不映射，即全区间）
	guestUnlocked    bool
	launchLogPath    string // 当前启动日志路径（版本目录下的 QGL\Logs）
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{
		downloadList:  make([]DownloadItem, 0),
		guestUnlocked: false,
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
