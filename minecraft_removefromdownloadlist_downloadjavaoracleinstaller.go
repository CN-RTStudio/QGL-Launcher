package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

)

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
