package main

import (

)

func (a *App) GetDownloadListCount() int {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	return len(a.downloadList)
}

// StartDownloadList 开始下载列表中的所有项目
// 下载中的任何时刻都可以再次调用：若已在下载中则直接返回（运行中的循环会继续拾取 pending 项），
// 只下载 pending 状态的项（失败/取消/已完成/下载中的都不会重复下载）
