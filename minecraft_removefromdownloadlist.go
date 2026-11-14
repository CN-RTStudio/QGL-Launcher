package main

import (
	"archive/zip"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) RemoveFromDownloadList(customName string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for i, item := range a.downloadList {
		if item.CustomName == customName {
			a.downloadList = append(a.downloadList[:i], a.downloadList[i+1:]...)
			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
			return nil
		}
	}
	return fmt.Errorf("未找到: %s", customName)
}

// GetDownloadList 获取下载列表
func (a *App) GetDownloadList() []DownloadItem {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	result := make([]DownloadItem, len(a.downloadList))
	copy(result, a.downloadList)
	return result
}

// GetDownloadListCount 获取下载列表数量
func (a *App) GetDownloadListCount() int {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	return len(a.downloadList)
}

// StartDownloadList 开始下载列表中的所有项目
// 下载中的任何时刻都可以再次调用：若已在下载中则直接返回（运行中的循环会继续拾取 pending 项），
// 只下载 pending 状态的项（失败/取消/已完成/下载中的都不会重复下载）
func (a *App) StartDownloadList() error {
	a.downloadMutex.Lock()
	if a.isDownloading {
		a.downloadMutex.Unlock()
		return nil // 已在下载中，循环会自动处理剩余 pending 项
	}
	if len(a.downloadList) == 0 {
		a.downloadMutex.Unlock()
		return fmt.Errorf("下载列表为空")
	}
	hasPending := false
	for i := range a.downloadList {
		if a.downloadList[i].Status == "pending" {
			hasPending = true
			break
		}
	}
	if !hasPending {
		a.downloadMutex.Unlock()
		return fmt.Errorf("没有待下载的项目")
	}
	a.isDownloading = true
	a.downloadCancel = make(chan struct{})
	a.downloadMutex.Unlock()

	go func() {
		defer func() {
			// 捕获任何 panic，保证 isDownloading 一定复位、完成事件一定发出，
			// 否则前端下载按钮会永久卡在"下载中"
			if r := recover(); r != nil {
				a.writeLog("下载列表处理发生崩溃: %v", r)
				a.downloadMutex.Lock()
				for i := range a.downloadList {
					if a.downloadList[i].Status == "downloading" {
						a.downloadList[i].Status = "failed"
						a.downloadList[i].ErrorMsg = fmt.Sprintf("内部错误: %v", r)
					}
					if a.downloadList[i].Status == "pending" {
						a.downloadList[i].Status = "cancelled"
					}
				}
				a.downloadMutex.Unlock()
			}
			a.downloadMutex.Lock()
			a.isDownloading = false
			a.downloadCancel = nil
			a.downloadMutex.Unlock()
			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
			runtime.EventsEmit(a.ctx, "downloadListCompleted")
		}()

		for {
			// 检查是否取消
			select {
			case <-a.downloadCancel:
				// 将所有 pending 状态重置（downloading 的保持不变）
				a.downloadMutex.Lock()
				for i := range a.downloadList {
					if a.downloadList[i].Status == "pending" {
						a.downloadList[i].Status = "cancelled"
					}
				}
				a.downloadMutex.Unlock()
				runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
				return
			default:
			}

			a.downloadMutex.Lock()
			var item *DownloadItem
			idx := -1
			for i := range a.downloadList {
				if a.downloadList[i].Status == "pending" {
					item = &a.downloadList[i]
					idx = i
					break
				}
			}
			if item == nil {
				a.downloadMutex.Unlock()
				break
			}
			a.downloadList[idx].Status = "downloading"
			a.downloadMutex.Unlock()

			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())

			var err error
			// 每个项目重置进度映射为全区间（各函数内部会按阶段重新划分）
			a.setProgressScale(0, 100)
			if item.ItemType == "java" {
				err = a.downloadJavaItem(item.JavaMajor, item.URL)
			} else if item.ItemType == "mod" {
				err = a.downloadModItem(item)
			} else if item.ItemType == "loader" {
				err = a.downloadLoaderItem(item)
			} else if item.ItemType == "modpack" {
				err = a.installModpack(item)
			} else if item.ItemType == "game+loader" {
				// 原版下载占 0-65%，加载器安装占 65-95%，验证占 95-100%
				a.emitProgress("downloading", "下载原版游戏 "+item.ID, 0, 0)
				a.setProgressScale(0, 65)
				if err = a.DownloadVersion(item.ID, item.URL, item.ID); err != nil {
					err = fmt.Errorf("下载原版游戏失败: %v", err)
				} else {
					a.setProgressScale(65, 95)
					a.emitProgress("downloading", "安装 "+item.LoaderName+" "+item.LoaderVersion, 0, 0)
					switch item.LoaderName {
					case "forge":
						err = a.InstallForge(item.ID, item.LoaderVersion)
					case "fabric":
						err = a.InstallFabric(item.ID, item.LoaderVersion)
					case "neoforge":
						err = a.InstallNeoForge(item.ID, item.LoaderVersion)
					case "optifine":
						err = a.InstallOptiFine(item.ID, item.OptiFineType, item.OptiFinePatch)
					}
					if err != nil {
						err = fmt.Errorf("安装加载器失败: %v", err)
					}
				}
			} else {
				err = a.DownloadVersion(item.ID, item.URL, item.CustomName)
			}

			a.downloadMutex.Lock()
			if err != nil {
				a.downloadList[idx].Status = "failed"
				a.downloadList[idx].Progress = 0
				a.downloadList[idx].CurrentStep = ""
				a.downloadList[idx].ErrorMsg = err.Error()
			} else {
				a.downloadList[idx].Status = "completed"
				a.downloadList[idx].Progress = 100
				a.downloadList[idx].CurrentStep = ""
			}
			a.downloadMutex.Unlock()

			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
		}
	}()

	return nil
}

// CancelDownloadList 取消下载列表中的剩余任务
func (a *App) CancelDownloadList() error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	if !a.isDownloading || a.downloadCancel == nil {
		return fmt.Errorf("当前没有正在进行的下载")
	}
	close(a.downloadCancel)
	return nil
}

// downloadJavaItem 下载 Java：优先通过 Mojang 官方 java-runtime 清单下载免安装运行时
// （参考 PCL，官方源 + BMCLAPI 镜像，32 线程并发，装到 <minecraftDir>/runtime/）；
// 清单中没有该版本（如 Java 26）或下载失败时，回退到 Oracle 安装包
func (a *App) downloadJavaItem(majorVer int, url string) error {
	if err := a.downloadJavaRuntime(majorVer); err != nil {
		a.writeLog("Mojang 运行时下载 Java %d 失败: %v，回退 Oracle 安装包", majorVer, err)
		return a.downloadJavaOracleInstaller(majorVer, url)
	}
	return nil
}

// downloadJavaOracleInstaller 回退方案：下载 Oracle 安装包并运行
func (a *App) downloadJavaOracleInstaller(majorVer int, url string) error {
	javaList := a.GetJavaDownloadList()
	var target *JavaDownloadInfo
	for i := range javaList {
		if javaList[i].MajorVer == majorVer {
			target = &javaList[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("未找到 Java %d 的下载信息", majorVer)
	}

	// 如果是网页链接（回退方案），用系统默认浏览器打开 Oracle 官方下载页
	if target.IsWebPage {
		webURL := target.URL
		if webURL == "" {
			webURL = url
		}
		cmd := exec.Command("cmd", "/c", "start", webURL)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Run()
	}

	// 下载到 %temp%
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	destPath := filepath.Join(tempDir, target.FileName)

	// 如果文件已存在，直接运行
	if _, err := os.Stat(destPath); err == nil {
		return runInstaller(destPath, target.IsMSI)
	}

	// 多线程分段下载安装包
	a.emitProgress("downloading", target.FileName, 0, 0)
	if err := a.downloadFileMultiThread(url, destPath, 8); err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}

	// 下载完成，运行安装程序
	return runInstaller(destPath, target.IsMSI)
}

// runInstaller 运行安装程序
func runInstaller(filePath string, isMSI bool) error {
	if isMSI {
		cmd := exec.Command("msiexec", "/i", filePath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Start()
	}
	cmd := exec.Command("cmd", "/c", "start", "", filePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

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
func (a *App) fixMissingLibraries(mcDir string, versionJSON *VersionJSON) {
	libsDir := filepath.Join(mcDir, "libraries")
	missingCount := 0
	downloadedCount := 0
	hashFailCount := 0

	// 预统计需要检查的库数量（用于进度百分比）
	totalLibs := 0
	for _, lib := range versionJSON.Libraries {
		if a.shouldIncludeLib(lib) {
			totalLibs++
		}
	}
	processedLibs := 0
	var lastLibEmit time.Time

	for _, lib := range versionJSON.Libraries {
		// 跳过不适用于当前平台的库
		if !a.shouldIncludeLib(lib) {
			continue
		}

		// 每 300ms 上报一次库文件检查进度（含百分比，避免用户以为卡死）
		processedLibs++
		if time.Since(lastLibEmit) > 300*time.Millisecond {
			lastLibEmit = time.Now()
			pct := 0
			if totalLibs > 0 {
				pct = processedLibs * 100 / totalLibs
			}
			a.emitFixProgress(fmt.Sprintf("补全文件 %d/%d (%d%%)", processedLibs, totalLibs, pct), int64(processedLibs), int64(totalLibs))
		}

		// 处理 natives 库：确保 native jar 文件存在
		if lib.Natives != nil {
			nativeKey, ok := lib.Natives["windows"]
			if !ok {
				continue
			}
			// 替换 ${arch} 占位符
			nativeKey = strings.ReplaceAll(nativeKey, "${arch}", "64")

			var nativePath string
			var nativeURL string
			var nativeSHA1 string

			if lib.Downloads != nil && lib.Downloads.Classifiers != nil {
				classifier, ok := lib.Downloads.Classifiers[nativeKey]
				if ok && classifier != nil {
					nativePath = filepath.Join(libsDir, classifier.Path)
					nativeURL = classifier.URL
					nativeSHA1 = classifier.SHA1
				}
			}

			if nativePath == "" {
				// 从 Maven 坐标推算路径
				nativePath = mavenNameToPath(lib.Name+"-"+nativeKey, libsDir)
			}

			if nativePath == "" {
				continue
			}

			// 检查 native jar 是否存在且校验通过
			if a.checkFileHash(nativePath, nativeSHA1) {
				continue
			}

			missingCount++

			// 尝试下载 native jar
			if nativeURL != "" {
				urls := a.getMirrorURLs(nativeURL)
				if a.downloadFromMirrors(urls, nativePath) {
					downloadedCount++
					a.writeLog("补全 native 库: %s", filepath.Base(nativePath))
				} else {
					a.writeLog("补全 native 库失败: %s", filepath.Base(nativePath))
				}
			}
			continue
		}

		// 确定库文件路径、URL、SHA1
		var libPath string
		var downloadURL string
		var expectedSHA1 string

		if lib.Downloads != nil && lib.Downloads.Artifact != nil && lib.Downloads.Artifact.Path != "" {
			libPath = filepath.Join(libsDir, lib.Downloads.Artifact.Path)
			downloadURL = lib.Downloads.Artifact.URL
			expectedSHA1 = lib.Downloads.Artifact.SHA1
		} else if lib.JarPath != "" {
			libPath = filepath.Join(libsDir, lib.JarPath)
			downloadURL = lib.URL
		} else if lib.Name != "" {
			libPath = mavenNameToPath(lib.Name, libsDir)
			downloadURL = ""
		}

		if libPath == "" {
			continue
		}

		// 检查文件是否存在且 SHA1 校验通过（参考 PCL 的 FileChecker）
		if a.checkFileHash(libPath, expectedSHA1) {
			continue
		}

		// 文件不存在或 SHA1 不匹配
		if _, err := os.Stat(libPath); err == nil && expectedSHA1 == "" {
			continue // 文件存在且无 SHA1 要求，跳过
		}

		if _, err := os.Stat(libPath); err == nil && expectedSHA1 != "" {
			hashFailCount++
			a.writeLog("库文件 SHA1 校验失败，重新下载: %s", filepath.Base(libPath))
		} else {
			missingCount++
		}

		// 尝试下载
		if downloadURL == "" {
			// 没有 URL，尝试从 Maven 坐标构建 URL
			downloadURL = mavenNameToURL(lib.Name)
		}

		if downloadURL == "" {
			a.writeLog("库文件缺失且无下载地址: %s", libPath)
			continue
		}

		// 获取多个镜像 URL（参考 PCL 的多源下载）
		urls := a.getMirrorURLs(downloadURL)

		// 删除损坏的文件
		if _, err := os.Stat(libPath); err == nil {
			os.Remove(libPath)
		}

		os.MkdirAll(filepath.Dir(libPath), 0755)
		if a.downloadFromMirrors(urls, libPath) {
			downloadedCount++
			a.writeLog("补全库文件: %s", filepath.Base(libPath))
		} else {
			a.writeLog("补全库文件失败: %s", filepath.Base(libPath))
		}
	}

	// 补全游戏主 jar（参考 PCL 的 DlClientJarGet）
	jarName := versionJSON.Jar
	if jarName == "" {
		jarName = versionJSON.InheritsFrom
	}
	if jarName == "" {
		jarName = versionJSON.ID
	}
	versionJar := filepath.Join(mcDir, "versions", jarName, jarName+".jar")
	var jarSHA1 string
	if versionJSON.Downloads != nil && versionJSON.Downloads.Client != nil {
		jarSHA1 = versionJSON.Downloads.Client.SHA1
	}

	if !a.checkFileHash(versionJar, jarSHA1) {
		if versionJSON.Downloads != nil && versionJSON.Downloads.Client != nil && versionJSON.Downloads.Client.URL != "" {
			os.MkdirAll(filepath.Dir(versionJar), 0755)
			url := versionJSON.Downloads.Client.URL
			urls := a.getMirrorURLs(url)
			// 替换特殊路径
			for i, u := range urls {
				urls[i] = strings.Replace(u, "https://launcher.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
				urls[i] = strings.Replace(urls[i], "https://piston-data.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
				urls[i] = strings.Replace(urls[i], "https://piston-meta.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
			}
			if a.downloadFromMirrors(urls, versionJar) {
				downloadedCount++
				a.writeLog("补全游戏 jar: %s", jarName)
			} else {
				a.writeLog("补全游戏 jar 失败: %s", jarName)
			}
		}
	}

	// 补全资源文件索引（参考 PCL 的 DlClientAssetIndexGet）
	a.fixAssetsIndex(mcDir, versionJSON)

	if missingCount > 0 || hashFailCount > 0 {
		a.writeLog("库文件补全完成: 缺失 %d 个, SHA1 不匹配 %d 个, 成功下载 %d 个", missingCount, hashFailCount, downloadedCount)
	}
}

// checkFileHash 检查文件是否存在且 SHA1 校验通过（参考 PCL 的 FileChecker.Check）
// 如果 SHA1 为空，只检查文件是否存在
func (a *App) checkFileHash(filePath string, expectedSHA1 string) bool {
	info, err := os.Stat(filePath)
	if err != nil || info.Size() == 0 {
		return false
	}

	if expectedSHA1 == "" {
		return true // 无 SHA1 要求，文件存在即可
	}

	// 计算 SHA1
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}

	actualSHA1 := fmt.Sprintf("%x", h.Sum(nil))
	return strings.EqualFold(actualSHA1, expectedSHA1)
}

// getMirrorURLs 获取多个镜像下载 URL（参考 PCL 的多源下载策略）
// 返回的 URL 列表按优先级排列：镜像源优先，官方源作为备用
func (a *App) getMirrorURLs(originalURL string) []string {
	var urls []string

	// Forge Maven
	if strings.Contains(originalURL, "maven.minecraftforge.net") {
		mirrorURL := strings.Replace(originalURL, "https://maven.minecraftforge.net/", "https://bmclapi2.bangbang93.com/maven/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// NeoForge Maven
	if strings.Contains(originalURL, "maven.neoforged.net") {
		mirrorURL := strings.Replace(originalURL, "https://maven.neoforged.net/releases/", "https://bmclapi2.bangbang93.com/maven/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// Fabric Maven
	if strings.Contains(originalURL, "maven.fabricmc.net") {
		mirrorURL := strings.Replace(originalURL, "https://maven.fabricmc.net/", "https://bmclapi2.bangbang93.com/maven/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// Minecraft 官方库
	if strings.Contains(originalURL, "libraries.minecraft.net") {
		mirrorURL := strings.Replace(originalURL, "https://libraries.minecraft.net/", "https://bmclapi2.bangbang93.com/libraries/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// Maven Central
	if strings.Contains(originalURL, "repo1.maven.org") {
		mirrorURL := strings.Replace(originalURL, "https://repo1.maven.org/maven2/", "https://bmclapi2.bangbang93.com/maven/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// Mojang 资源
	if strings.Contains(originalURL, "launcher.mojang.com") || strings.Contains(originalURL, "piston-data.mojang.com") || strings.Contains(originalURL, "piston-meta.mojang.com") {
		mirrorURL := strings.Replace(originalURL, "https://launcher.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
		mirrorURL = strings.Replace(mirrorURL, "https://piston-data.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
		mirrorURL = strings.Replace(mirrorURL, "https://piston-meta.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// 资源文件
	if strings.Contains(originalURL, "resources.download.minecraft.net") {
		mirrorURL := strings.Replace(originalURL, "https://resources.download.minecraft.net/", "https://bmclapi2.bangbang93.com/assets/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// 默认：原 URL
	urls = append(urls, originalURL)
	return urls
}

// downloadFromMirrors 从多个镜像源尝试下载（参考 PCL 的多源下载策略）
func (a *App) downloadFromMirrors(urls []string, destPath string) bool {
	for _, url := range urls {
		// 删除可能存在的损坏文件
		os.Remove(destPath)
		os.MkdirAll(filepath.Dir(destPath), 0755)

		if err := a.downloadFile(url, destPath, false); err != nil {
			a.writeLog("下载失败 [%s]: %v", url, err)
			continue
		}
		return true
	}
	return false
}

// fixAssetsIndex 补全资源文件索引（参考 PCL 的 DlClientAssetIndexGet）
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
func mavenNameToURL(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}

	group := strings.ReplaceAll(parts[0], ".", "/")
	artifact := parts[1]
	version := parts[2]
	classifier := ""
	if len(parts) >= 4 {
		classifier = "-" + parts[3]
	}

	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)
	return fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s", group, artifact, version, fileName)
}

// extractNatives 从 jar 中提取 dll/jnilib/so 文件到目标目录
// 返回提取的文件数量
// 增强：处理损坏的 jar 文件、清理多余文件（参考 PCL 的 McLaunchNatives）
func extractNatives(jarPath string, destDir string) (int, error) {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		// 损坏的 jar 文件，删除它（参考 PCL：删除损坏的 Natives 文件）
		os.Remove(jarPath)
		return 0, fmt.Errorf("打开 Natives 文件失败（文件可能已损坏）: %s", jarPath)
	}
	defer r.Close()

	count := 0
	var extractedFiles []string // 记录本次提取的文件名，用于清理多余文件

	for _, f := range r.File {
		// 跳过目录和 META-INF
		if f.FileInfo().IsDir() {
			continue
		}
		if strings.HasPrefix(f.Name, "META-INF/") {
			continue
		}

		// 只提取 .dll, .jnilib, .so 文件
		lowerName := strings.ToLower(f.Name)
		if !strings.HasSuffix(lowerName, ".dll") &&
			!strings.HasSuffix(lowerName, ".jnilib") &&
			!strings.HasSuffix(lowerName, ".so") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		fileName := filepath.Base(f.Name)
		destPath := filepath.Join(destDir, fileName)
		extractedFiles = append(extractedFiles, destPath)

		// 如果文件已存在且大小相同，跳过（参考PCL）
		if info, err := os.Stat(destPath); err == nil && info.Size() == f.FileInfo().Size() {
			rc.Close()
			count++
			continue
		}

		// 文件存在但大小不同，删除旧文件（参考 PCL）
		if _, err := os.Stat(destPath); err == nil {
			os.Remove(destPath)
		}

		out, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			continue
		}

		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			continue
		}
		count++
	}

	return count, nil
}

// extractNativesFromJSON 从版本 JSON 的 libraries 中提取 natives
// 增强：支持 natives-windows-64 键、处理损坏的 jar（参考 PCL 的 McLaunchNatives）
func (a *App) extractNativesFromJSON(mcDir string, nativesDir string, versionJSON *VersionJSON) {
	// 确保 natives 目录存在
	os.MkdirAll(nativesDir, 0755)

	// 记录所有提取的文件路径，用于清理多余文件（参考 PCL）
	var allExtractedFiles []string

	for _, lib := range versionJSON.Libraries {
		if lib.Natives == nil {
			continue
		}

		// 尝试多个 native 键（参考 PCL 的 McLibListGetWithJson）
		// 优先级: natives-windows-64 > natives-windows
		nativeKey := ""
		if key, ok := lib.Natives["windows-64"]; ok {
			nativeKey = strings.ReplaceAll(key, "${arch}", "64")
		} else if key, ok := lib.Natives["windows"]; ok {
			nativeKey = strings.ReplaceAll(key, "${arch}", "64")
		}

		if nativeKey == "" {
			continue
		}

		if lib.Downloads == nil || lib.Downloads.Classifiers == nil {
			continue
		}
		classifier, ok := lib.Downloads.Classifiers[nativeKey]
		if !ok || classifier == nil {
			continue
		}
		nativeJarPath := filepath.Join(mcDir, "libraries", classifier.Path)

		// 检查 native jar 是否存在
		if _, err := os.Stat(nativeJarPath); os.IsNotExist(err) {
			a.writeLog("native jar 不存在(跳过): %s", nativeJarPath)
			continue
		}

		extracted, err := extractNatives(nativeJarPath, nativesDir)
		if err != nil {
			a.writeLog("解压 native 失败: %s, %v", classifier.Path, err)
		} else if extracted > 0 {
			a.writeLog("解压 native: %s -> %d 个文件", classifier.Path, extracted)
		}
	}

	// 清理 natives 目录中的多余文件（参考 PCL 的 McLaunchNatives）
	// 如果 allExtractedFiles 非空，删除不在列表中的 .dll/.so/.jnilib 文件
	_ = allExtractedFiles // 暂时不清理，避免误删（PCL 也有此保护逻辑）
}

// isDirEmpty 检查目录是否为空
func isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true, err
	}
	return len(entries) == 0, nil
}

// setGameLanguage 设置游戏语言为中文（参考 PCL 的 options.txt 修改逻辑）
// 修改游戏目录下的 options.txt 中的 lang 字段
// MC 版本语言格式：
//   1.1~1.5: zh_CN（最后两位必须大写，否则崩溃）
//   1.6~1.10: zh_CN（zh_cn 会自动切换为英文）
//   1.11~1.12: zh_cn（zh_CN 虽然显示中文但语言设置会错误显示英文）
//   1.13+: zh_cn（zh_CN 会自动切换为英文）
func (a *App) setGameLanguage(gameDir string, versionID string) {
	optionsPath := filepath.Join(gameDir, "options.txt")

	// 提取 MC 主版本号
	mcCodeMain := 0
	parts := strings.Split(versionID, "-")
	if len(parts) > 0 {
		verParts := strings.Split(parts[0], ".")
		if len(verParts) >= 2 {
			if v, err := strconv.Atoi(verParts[1]); err == nil {
				mcCodeMain = v
			}
		}
	}

	// 确定语言代码
	requiredLang := "zh_cn"
	if mcCodeMain > 0 && mcCodeMain < 12 {
		// 1.1~1.11 需要大写后缀
		requiredLang = "zh_CN"
	}

	// 检查 Yosbr Mod 兼容
	if _, err := os.Stat(optionsPath); os.IsNotExist(err) {
		yosbrPath := filepath.Join(gameDir, "config", "yosbr", "options.txt")
		if _, err2 := os.Stat(yosbrPath); err2 == nil {
			optionsPath = yosbrPath
			a.writeLog("检测到 Yosbr Mod，修改其 options.txt")
		}
	}

	// 读取 options.txt
	data, err := os.ReadFile(optionsPath)
	if err != nil {
		// 文件不存在，创建新的
		content := fmt.Sprintf("lang:%s\n", requiredLang)
		if err := os.WriteFile(optionsPath, []byte(content), 0644); err != nil {
			a.writeLog("创建 options.txt 失败: %v", err)
		} else {
			a.writeLog("已创建 options.txt，设置语言为 %s", requiredLang)
		}
		return
	}

	// 解析并修改 lang 字段
	lines := strings.Split(string(data), "\n")
	found := false
	hasSaves := false
	// 检查是否有存档目录（有存档说明不是首次启动，不强制修改语言）
	if info, err := os.Stat(filepath.Join(gameDir, "saves")); err == nil && info.IsDir() {
		hasSaves = true
	}

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "lang:") {
			currentLang := strings.TrimSpace(strings.TrimPrefix(line, "lang:"))
			if currentLang == requiredLang {
				a.writeLog("游戏语言已为 %s，无需修改", requiredLang)
				return
			}
			// 如果有存档，不强制修改用户已有的语言设置
			if hasSaves && currentLang != "" && currentLang != "none" {
				a.writeLog("检测到已有存档，保留用户语言设置: %s", currentLang)
				return
			}
			lines[i] = fmt.Sprintf("lang:%s", requiredLang)
			found = true
			break
		}
	}

	if !found {
		// 没有找到 lang 行，添加
		lines = append(lines, fmt.Sprintf("lang:%s", requiredLang))
	}

	// 写回文件
	newData := strings.Join(lines, "\n")
	if err := os.WriteFile(optionsPath, []byte(newData), 0644); err != nil {
		a.writeLog("写入 options.txt 失败: %v", err)
	} else {
		a.writeLog("已将游戏语言设置为 %s", requiredLang)
	}
}

// ensureNativesForLoader 为加载器版本确保 natives 存在
// 原版下载时 natives 解压到了 versions/{mcVersion}/{mcVersion}-natives，
// 但加载器版本（Forge/Fabric/NeoForge）启动时需要 versions/{loaderVersion}/{loaderVersion}-natives
