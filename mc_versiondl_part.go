package main

import (
	"os"
	"strings"
	"time"
)

// checkFileHash 校验文件完整性（SHA1，用于验证 Mojang manifest 提供的哈希）
func (a *App) checkFileHash(filePath string, expectedSHA1 string) bool {
	info, err := os.Stat(filePath)
	if err != nil || info.Size() == 0 {
		return false
	}
	expected := strings.ToLower(strings.TrimSpace(expectedSHA1))
	if expected == "" {
		return true
	}
	return fileSHA1Matches(filePath, expected)
}

func (a *App) getMirrorURLs(originalURL string) []string {
	var urls []string
	addMirror := func(mirror, original string) {
		urls = append(urls, mirror, original)
	}
	switch {
	case strings.Contains(originalURL, "maven.minecraftforge.net"):
		addMirror(rewriteMavenLibURLToBMCL(originalURL), originalURL)
	case strings.Contains(originalURL, "maven.neoforged.net"):
		addMirror(rewriteMavenLibURLToBMCL(originalURL), originalURL)
	case strings.Contains(originalURL, "maven.fabricmc.net"):
		addMirror(rewriteMavenLibURLToBMCL(originalURL), originalURL)
	case strings.Contains(originalURL, "libraries.minecraft.net"):
		addMirror(rewriteLibraryArtifactURLToBMCL(originalURL), originalURL)
	case strings.Contains(originalURL, "repo1.maven.org"):
		addMirror(rewriteMavenCentralURLToBMCL(originalURL), originalURL)
	case strings.Contains(originalURL, "launcher.mojang.com"), strings.Contains(originalURL, "piston-data.mojang.com"), strings.Contains(originalURL, "piston-meta.mojang.com"):
		m := rewriteObjectVersionURLToBMCL(originalURL)
		addMirror(m, originalURL)
	case strings.Contains(originalURL, "resources.download.minecraft.net"):
		addMirror(rewriteAssetURLToBMCL(originalURL), originalURL)
	default:
		urls = append(urls, originalURL)
	}
	return urls
}

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
