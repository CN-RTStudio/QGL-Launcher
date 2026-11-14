package main

import (
	"fmt"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) emitFixProgress(step string, done, total int64) {
	a.emitProgress("downloading", step, done, total)
	runtime.EventsEmit(a.ctx, "launchFixProgress", step)
}

// formatBytesForProgress 将字节数格式化为 MB 显示（进度步骤文本用）
func formatBytesForProgress(b int64) string {
	return fmt.Sprintf("%.1f MB", float64(b)/1024/1024)
}

// downloadFileMultiThread 多线程分段下载单个文件（参考补全文件的并发思路）
// 通过 HTTP Range 将文件分成 threads 段并行下载；服务器不支持 Range 时自动回退单线程
// 进度通过 emitProgress 上报（文件名 + 已下载字节/总字节），total<=0 时步骤文本显示已下载量
