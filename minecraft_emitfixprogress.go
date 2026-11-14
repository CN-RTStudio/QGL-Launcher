package main

import (

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) emitFixProgress(step string, done, total int64) {
	a.emitProgress("downloading", step, done, total)
	runtime.EventsEmit(a.ctx, "launchFixProgress", step)
}

// formatBytesForProgress 将字节数格式化为 MB 显示（进度步骤文本用）
