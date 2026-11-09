package main

import (
	"os"
	"time"
)

func (a *App) downloadFromMirrors(urls []string, destPath string, maxBytes int64) bool {
	plan := planMirrorAttempts(urls, time.Now())
	for attempt, url := range plan.URLs {
		if plan.expired(time.Now()) {
			a.writeLog("镜像回退超出总预算 %s，放弃剩余镜像", plan.Budget)
			return false
		}
		os.Remove(destPath)
		if err := a.downloadFileBounded(url, destPath, false, maxBytes); err != nil {
			a.writeLog("下载失败 [%s]: %v", url, err)
			// 切下一个镜像前做一次可中断的退避（mt_xor25 抖动 ±25%），
			// 既避免失败后瞬间重试压垮镜像，也让多实例不会同步重试；取消下载立即返回。
			if attempt+1 < len(plan.URLs) {
				if !a.sleepOrCancel(mtXor25Jitter(mirrorFallbackDelay(attempt))) {
					return false
				}
			}
			continue
		}
		return true
	}
	return false
}

// sleepOrCancel 休眠 d，期间若下载列表被取消则立即返回 false；正常到点返回 true。
func (a *App) sleepOrCancel(d time.Duration) bool {
	a.downloadMutex.Lock()
	ch := a.downloadCancel
	a.downloadMutex.Unlock()
	if ch == nil {
		time.Sleep(d)
		return true
	}
	select {
	case <-ch:
		return false
	case <-time.After(d):
		return true
	}
}
