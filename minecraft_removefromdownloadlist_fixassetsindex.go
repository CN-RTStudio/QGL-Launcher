package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
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
