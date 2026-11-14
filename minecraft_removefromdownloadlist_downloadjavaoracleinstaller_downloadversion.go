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

func (a *App) DownloadVersion(versionID string, versionURL string, customName string) error {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", customName)

	// 1. 创建版本目录
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}

	// 2. 下载版本 JSON（使用 BMCLAPI 镜像）
	a.emitProgress("downloading", customName+".json", 0, 0)
	jsonURL := replaceWithBMCLAPI(versionURL)
	jsonPath := filepath.Join(versionDir, customName+".json")
	if err := a.downloadFile(jsonURL, jsonPath, false); err != nil {
		return fmt.Errorf("下载版本 JSON 失败: %v", err)
	}

	// 读取并解析版本 JSON
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("读取版本 JSON 失败: %v", err)
	}

	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	// 3. 下载客户端 jar（多线程分段下载）
	if versionJSON.Downloads != nil && versionJSON.Downloads.Client != nil {
		client := versionJSON.Downloads.Client
		clientURL := replaceWithBMCLAPI(client.URL)
		jarPath := filepath.Join(versionDir, customName+".jar")
		a.emitProgress("downloading", customName+".jar", 0, client.Size)
		if err := a.downloadFileMultiThread(clientURL, jarPath, 8); err != nil {
			return fmt.Errorf("下载客户端 jar 失败: %v", err)
		}
	}

	// 4. 并发下载库文件（包括 artifact 和 natives），与补全文件相同的并发模式
	{
		type libTask struct {
			url  string
			path string
		}
		tasks := make([]libTask, 0)
		for _, lib := range versionJSON.Libraries {
			if lib.Downloads == nil {
				continue
			}
			if lib.Downloads.Artifact != nil {
				artifact := lib.Downloads.Artifact
				libPath := filepath.Join(mcDir, "libraries", artifact.Path)
				if info, err := os.Stat(libPath); err == nil && info.Size() > 0 {
					continue // 已存在，跳过
				}
				tasks = append(tasks, libTask{url: replaceWithBMCLAPI(artifact.URL), path: libPath})
			}
			if lib.Natives != nil {
				nativeKey, ok := lib.Natives["windows"]
				if !ok {
					continue
				}
				nativeKey = strings.ReplaceAll(nativeKey, "${arch}", "64")
				if lib.Downloads.Classifiers == nil {
					continue
				}
				classifier, ok := lib.Downloads.Classifiers[nativeKey]
				if !ok || classifier == nil {
					continue
				}
				nativePath := filepath.Join(mcDir, "libraries", classifier.Path)
				if info, err := os.Stat(nativePath); err == nil && info.Size() > 0 {
					continue
				}
				tasks = append(tasks, libTask{url: replaceWithBMCLAPI(classifier.URL), path: nativePath})
			}
		}

		total := int64(len(tasks))
		var (
			wg        sync.WaitGroup
			taskCh    = make(chan libTask)
			doneCount int64
			lastEmit  time.Time
			emitMu    sync.Mutex
		)
		workers := 32
		if workers > len(tasks) && len(tasks) > 0 {
			workers = len(tasks)
		}
		if workers > 0 {
			wg.Add(workers)
			for w := 0; w < workers; w++ {
				go func() {
					defer wg.Done()
					for task := range taskCh {
						os.MkdirAll(filepath.Dir(task.path), 0755)
						if err := a.downloadFile(task.url, task.path, false); err != nil {
							fmt.Printf("下载库文件失败(跳过): %s, %v\n", filepath.Base(task.path), err)
						}
						done := atomic.AddInt64(&doneCount, 1)
						emitMu.Lock()
						if time.Since(lastEmit) > 300*time.Millisecond {
							lastEmit = time.Now()
							emitMu.Unlock()
							a.emitProgress("downloading", fmt.Sprintf("库文件 %d/%d (%d%%)", done, total, done*100/total), done, total)
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
		}
	}

	// 5. 下载资源索引 + 并发下载资源文件
	if versionJSON.AssetIndex != nil {
		assetIndexRef := versionJSON.AssetIndex
		assetIndexDir := filepath.Join(mcDir, "assets", "indexes")
		assetIndexPath := filepath.Join(assetIndexDir, assetIndexRef.ID+".json")
		assetIndexURL := replaceWithBMCLAPI(assetIndexRef.URL)

		a.emitProgress("downloading", "资源索引", 0, 0)
		if err := a.downloadFile(assetIndexURL, assetIndexPath, false); err != nil {
			fmt.Printf("下载资源索引失败: %v\n", err)
		} else {
			assetIndexData, err := os.ReadFile(assetIndexPath)
			if err == nil {
				var assetIndex AssetIndex
				if json.Unmarshal(assetIndexData, &assetIndex) == nil {
					// 收集缺失的资源，32 线程并发下载
					type assetTask struct {
						url  string
						path string
					}
					tasks := make([]assetTask, 0)
					for _, obj := range assetIndex.Objects {
						hash := obj.Hash
						subHash := hash[:2]
						assetPath := filepath.Join(mcDir, "assets", "objects", subHash, hash)
						if info, err := os.Stat(assetPath); err == nil && info.Size() > 0 {
							continue
						}
						// 与补全文件相同的资源 URL 格式
						assetURL := replaceWithBMCLAPI(fmt.Sprintf("https://resources.download.minecraft.net/%s/%s", subHash, hash))
						tasks = append(tasks, assetTask{url: assetURL, path: assetPath})
					}

					total := int64(len(tasks))
					var (
						wg        sync.WaitGroup
						taskCh    = make(chan assetTask)
						doneCount int64
						lastEmit  time.Time
						emitMu    sync.Mutex
					)
					workers := 32
					if workers > len(tasks) && len(tasks) > 0 {
						workers = len(tasks)
					}
					if workers > 0 {
						wg.Add(workers)
						for w := 0; w < workers; w++ {
							go func() {
								defer wg.Done()
								for task := range taskCh {
									os.MkdirAll(filepath.Dir(task.path), 0755)
									if derr := a.downloadFile(task.url, task.path, false); derr != nil {
										fmt.Printf("下载资源失败(跳过): %s, %v\n", filepath.Base(task.path), derr)
									}
									done := atomic.AddInt64(&doneCount, 1)
									emitMu.Lock()
									if time.Since(lastEmit) > 300*time.Millisecond {
										lastEmit = time.Now()
										emitMu.Unlock()
										a.emitProgress("downloading", fmt.Sprintf("资源 %d/%d (%d%%)", done, total, done*100/total), done, total)
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
					}
				}
			}
		}
	}

	// 6. 解压 natives 到版本目录下的 natives 文件夹
	a.emitProgress("extracting", "natives", 0, 0)
	nativesDir := filepath.Join(versionDir, customName+"-natives")
	if err := os.MkdirAll(nativesDir, 0755); err != nil {
		return fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, &versionJSON)

	// 验证 natives 目录中是否有文件
	nativesEntries, err := os.ReadDir(nativesDir)
	if err == nil && len(nativesEntries) == 0 {
		a.writeLog("警告: natives 目录为空，游戏可能无法启动")
	}

	a.emitProgress("completed", "", 100, 100)
	return nil
}

// fixMissingLibraries 补全缺失的库文件（参考 PCL 的 DlClientFix + McLibFix）
// 增强功能：SHA1 校验、多镜像源、assets 补全、natives 库补全
