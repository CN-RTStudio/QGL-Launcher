package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

)

func (a *App) fixAssetsIndex(mcDir string, versionJSON *VersionJSON) {
	if versionJSON.AssetIndex == nil || versionJSON.AssetIndex.URL == "" {
		return
	}

	// 资源索引文件路径
	assetIndexDir := filepath.Join(mcDir, "assets", "indexes")
	assetIndexPath := filepath.Join(assetIndexDir, versionJSON.AssetIndex.ID+".json")

	// 检查索引文件是否存在
	if _, err := os.Stat(assetIndexPath); err == nil {
		// 索引文件已存在，仍需校验资源本体完整性（参考 PCL：每次启动都会跑一遍资源校验）
		// 之前索引存在就直接 return，导致下载不完整的资源永远不会被补全
		a.fixMissingAssets(mcDir, assetIndexPath)
		return
	}

	a.writeLog("资源索引文件缺失，正在下载: %s", versionJSON.AssetIndex.ID)

	os.MkdirAll(assetIndexDir, 0755)

	url := versionJSON.AssetIndex.URL
	urls := a.getMirrorURLs(url)
	// 替换特殊路径
	for i, u := range urls {
		urls[i] = strings.Replace(u, "https://piston-meta.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
		urls[i] = strings.Replace(urls[i], "https://launcher.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
	}

	if a.downloadFromMirrors(urls, assetIndexPath) {
		a.writeLog("资源索引文件下载完成: %s", versionJSON.AssetIndex.ID)

		// 解析索引文件，补全缺失的资源文件（参考 PCL 的 McAssetsFixList）
		a.fixMissingAssets(mcDir, assetIndexPath)
	} else {
		a.writeLog("资源索引文件下载失败: %s", versionJSON.AssetIndex.ID)
	}
}

// fixMissingAssets 补全缺失的资源文件（参考 PCL 的 McAssetsFixList）
func (a *App) fixMissingAssets(mcDir string, assetIndexPath string) {
	data, err := os.ReadFile(assetIndexPath)
	if err != nil {
		return
	}

	var index AssetIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return
	}

	objectsDir := filepath.Join(mcDir, "assets", "objects")
	var missingCount, downloadedCount, hashFailCount int64
	totalObjects := len(index.Objects)
	checkedCount := 0
	lastEmit := time.Time{}

	// ===== 阶段 1：快速扫描（纯文件大小校验，不联网），收集缺失列表 =====
	// 参考 PCL：启动时只查 Size 不算哈希，缺失文件收集后统一并发下载
	type assetTask struct {
		urls    []string
		objPath string
		size    int64
	}
	tasks := make([]assetTask, 0)

	for _, obj := range index.Objects {
		if obj.Hash == "" {
			continue
		}

		// 资源文件路径: assets/objects/{hash前2位}/{hash}
		objPath := filepath.Join(objectsDir, obj.Hash[:2], obj.Hash)

		needDownload := false
		info, err := os.Stat(objPath)
		if err != nil || info.Size() == 0 {
			needDownload = true
			missingCount++
		} else if obj.Size > 0 && info.Size() != obj.Size {
			// 文件大小与索引不符 → 下载不完整/损坏，删除重下
			// （参考 PCL 的资源校验：按 Size 校验，比逐个算 SHA1 快得多）
			needDownload = true
			hashFailCount++
			os.Remove(objPath)
		}

		// 每 300ms 上报一次扫描进度（含百分比）
		checkedCount++
		if time.Since(lastEmit) > 300*time.Millisecond {
			lastEmit = time.Now()
			pct := 0
			if totalObjects > 0 {
				pct = checkedCount * 100 / totalObjects
			}
			a.emitFixProgress(fmt.Sprintf("校验资源 %d/%d (%d%%)", checkedCount, totalObjects, pct), int64(checkedCount), int64(totalObjects))
		}

		if needDownload {
			// 下载 URL（参考 PCL 的 DlSourceAssetsGet）
			originalURL := fmt.Sprintf("https://resources.download.minecraft.net/%s/%s", obj.Hash[:2], obj.Hash)
			tasks = append(tasks, assetTask{urls: a.getMirrorURLs(originalURL), objPath: objPath, size: obj.Size})
		}
	}

	// ===== 阶段 2：并发下载缺失资源（PCL 用几十线程并行，串行逐个下载会慢几十倍）=====
	if len(tasks) > 0 {
		const workers = 32
		var (
			wg           sync.WaitGroup
			taskCh       = make(chan assetTask)
			doneCount    int64
			failCount    int64
			lastDlEmit   time.Time
			emitMu       sync.Mutex
		)
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for task := range taskCh {
					os.MkdirAll(filepath.Dir(task.objPath), 0755)
					if a.downloadFromMirrors(task.urls, task.objPath) {
						atomic.AddInt64(&downloadedCount, 1)
						// 下载后校验大小，失败说明下载不完整
						if info, err := os.Stat(task.objPath); err != nil || (task.size > 0 && info.Size() != task.size) {
							os.Remove(task.objPath)
							a.writeLog("资源文件下载后校验失败: %s", filepath.Base(task.objPath))
						}
					} else {
						atomic.AddInt64(&failCount, 1)
					}
					done := atomic.AddInt64(&doneCount, 1)
					// 上报下载进度（加锁避免时间戳竞争）
					emitMu.Lock()
					if time.Since(lastDlEmit) > 300*time.Millisecond {
						lastDlEmit = time.Now()
						emitMu.Unlock()
						pct := int(done) * 100 / len(tasks)
						a.emitFixProgress(fmt.Sprintf("下载资源 %d/%d (%d%%)", done, len(tasks), pct), done, int64(len(tasks)))
						continue
					}
					emitMu.Unlock()
				}
			}()
		}
		for _, task := range tasks {
			taskCh <- task
		}
		close(taskCh)
		wg.Wait()

		if failCount > 0 {
			a.writeLog("资源文件并发下载: %d 个失败", failCount)
		}
	}

	if missingCount > 0 || hashFailCount > 0 {
		a.writeLog("资源文件补全: 缺失 %d 个, 大小不匹配 %d 个, 成功下载 %d 个", missingCount, hashFailCount, downloadedCount)
		a.emitFixProgress(fmt.Sprintf("资源补全完成 (补下 %d 个)", downloadedCount), 0, 0)
	}
}

// mavenNameToURL 从 Maven 坐标推算下载 URL
