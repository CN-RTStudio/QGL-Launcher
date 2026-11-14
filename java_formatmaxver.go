package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func formatMaxVer(maxMajor int) string {
	if maxMajor <= 0 {
		return "无上限"
	}
	return fmt.Sprintf("%d", maxMajor)
}

// GetJavaInfo 获取指定路径的 Java 信息（供前端调用）
func (a *App) GetJavaInfo(javaPath string) *JavaEntry {
	if javaPath == "" {
		return nil
	}
	return validateJava(javaPath)
}

// ===== Java 下载功能 =====

// JavaDownloadInfo Java 下载信息
type JavaDownloadInfo struct {
	MajorVer  int    `json:"majorVer"`  // 主版本号
	Name      string `json:"name"`      // 显示名称
	URL       string `json:"url"`       // 下载链接
	FileName  string `json:"fileName"`  // 保存的文件名
	IsMSI     bool   `json:"isMSI"`     // 是否为 MSI 安装包
	IsZip     bool   `json:"isZip"`     // 是否为 ZIP 压缩包
	IsWebPage bool   `json:"isWebPage"` // 是否为网页链接（无法直接下载）
}

// GetJavaDownloadList 获取 Java 下载列表
// 回退方案为系统默认浏览器打开 Oracle 官方下载页（Mojang runtime 清单失败时使用）
func (a *App) GetJavaDownloadList() []JavaDownloadInfo {
	return []JavaDownloadInfo{
		{
			MajorVer:  27,
			Name:      "Java 27",
			URL:       "https://www.oracle.com/cn/java/technologies/downloads/#jdk27-windows",
			FileName:  "jdk-27-windows",
			IsMSI:     false,
			IsWebPage: true,
		},
		{
			MajorVer:  21,
			Name:      "Java 21",
			URL:       "https://www.oracle.com/cn/java/technologies/downloads/#java21-windows",
			FileName:  "jdk-21-windows",
			IsMSI:     false,
			IsWebPage: true,
		},
		{
			MajorVer:  17,
			Name:      "Java 17",
			URL:       "https://www.oracle.com/cn/java/technologies/downloads/#java17-windows",
			FileName:  "jdk-17-windows",
			IsMSI:     false,
			IsWebPage: true,
		},
		{
			MajorVer:  8,
			Name:      "Java 8",
			URL:       "https://www.oracle.com/cn/java/technologies/downloads/#java8-windows",
			FileName:  "java8-windows",
			IsMSI:     false,
			IsWebPage: true,
		},
	}
}

// ===== Mojang 官方 Java 运行时下载（参考 PCL 的 JavaFileList）=====

// mojangJavaRuntimeIndexURL Mojang java-runtime 清单索引（BMCLAPI 有镜像，替换域名即可）
const mojangJavaRuntimeIndexURL = "https://piston-meta.mojang.com/v1/products/java-runtime/2ec0cc96c44e5a76b9c8b7c39df7210883d12871/all.json"

// javaRuntimeManifest Mojang java-runtime 清单条目
type javaRuntimeEntry struct {
	Name     string `json:"name"`
	Version  struct {
		Name string `json:"name"`
	} `json:"version"`
	Manifest struct {
		URL string `json:"url"`
	} `json:"manifest"`
}

// javaRuntimeFileEntry runtime manifest 中的文件条目
type javaRuntimeFileEntry struct {
	Type      string `json:"type"`
	Downloads struct {
		Raw *struct {
			URL  string `json:"url"`
			Size int64  `json:"size"`
			SHA1 string `json:"sha1"`
		} `json:"raw"`
	} `json:"downloads"`
}

// fetchURLWithMirrors 依次尝试多个 URL 获取内容（先官方，失败走 BMCLAPI 镜像）
func fetchURLWithMirrors(urls []string) ([]byte, error) {
	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		return data, nil
	}
	return nil, lastErr
}

// downloadJavaRuntime 通过 Mojang 官方 java-runtime 清单下载并安装 Java（免安装版，参考 PCL 的 JavaFileList + LoaderDownload）
// 安装位置：<minecraftDir>/runtime/<运行时key>/，QGL 搜索 Java 时会扫描 .minecraft 目录自动发现
func (a *App) downloadJavaRuntime(majorVer int) error {
	a.writeLog("开始通过 Mojang 运行时清单下载 Java %d", majorVer)

	// 1. 获取索引（官方 → BMCLAPI 镜像）
	indexData, err := fetchURLWithMirrors([]string{
		mojangJavaRuntimeIndexURL,
		strings.Replace(mojangJavaRuntimeIndexURL, "piston-meta.mojang.com", "bmclapi2.bangbang93.com", 1),
	})
	if err != nil {
		return fmt.Errorf("获取 Java 运行时索引失败: %v", err)
	}

	var index map[string][]javaRuntimeEntry
	if err := json.Unmarshal(indexData, &index); err != nil {
		return fmt.Errorf("解析 Java 运行时索引失败: %v", err)
	}

	entries, ok := index["windows-x64"]
	if !ok || len(entries) == 0 {
		return fmt.Errorf("索引中没有 windows-x64 的 Java 运行时")
	}

	// 2. 从后往前找版本名匹配的运行时（最新的优先，同 PCL 的 Children.Reverse）
	majorStr := strconv.Itoa(majorVer)
	var target *javaRuntimeEntry
	for i := len(entries) - 1; i >= 0; i-- {
		if strings.HasPrefix(entries[i].Version.Name, majorStr) {
			target = &entries[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("Mojang 运行时清单中没有 Java %d", majorVer)
	}

	a.writeLog("选中 Java 运行时 %s（%s）", target.Version.Name, target.Name)

	// 3. 获取文件列表 manifest（官方 → BMCLAPI 镜像）
	manifestData, err := fetchURLWithMirrors([]string{
		target.Manifest.URL,
		strings.Replace(target.Manifest.URL, "piston-meta.mojang.com", "bmclapi2.bangbang93.com", 1),
	})
	if err != nil {
		return fmt.Errorf("获取 Java 文件列表失败: %v", err)
	}

	var manifest struct {
		Files map[string]javaRuntimeFileEntry `json:"files"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("解析 Java 文件列表失败: %v", err)
	}

	// 安装目录：<minecraftDir>/runtime/<key>/
	mcDir := a.getMinecraftDir()
	baseDir := filepath.Join(mcDir, "runtime", target.Name)

	// PCL 跳过的 3 个无意义重复文件（#3827）
	skipHashes := map[string]bool{
		"12976a6c2b227cbac58969c1455444596c894656": true,
		"c80e4bab46e34d02826eab226a4441d0970f2aba": true,
		"84d2102ad171863db04e7ee22a259d1f6c5de4a5": true,
	}

	// 4. 收集任务：目录直接创建，文件校验大小后并发下载
	type fileTask struct {
		url  string
		path string
		size int64
	}
	var fileTasks []fileTask
	totalFiles := 0
	for relPath, entry := range manifest.Files {
		destPath := filepath.Join(baseDir, filepath.FromSlash(relPath))
		if entry.Type == "directory" {
			os.MkdirAll(destPath, 0755)
			continue
		}
		if entry.Downloads.Raw == nil {
			continue
		}
		raw := entry.Downloads.Raw
		if skipHashes[raw.SHA1] {
			continue
		}
		totalFiles++
		// 已存在且大小一致则跳过
		if info, err := os.Stat(destPath); err == nil && info.Size() == raw.Size {
			continue
		}
		// 官方源优先，BMCLAPI 镜像回退
		fileTasks = append(fileTasks, fileTask{
			url:  raw.URL,
			path: destPath,
			size: raw.Size,
		})
	}

	// 5. 32 线程并发下载（与补全资源相同的模式）
	total := int64(totalFiles)
	var (
		wg        sync.WaitGroup
		taskCh    = make(chan fileTask)
		doneCount int64
		failCount int64
		lastEmit  time.Time
		emitMu    sync.Mutex
	)
	workers := 32
	if workers > len(fileTasks) && len(fileTasks) > 0 {
		workers = len(fileTasks)
	}
	if workers > 0 {
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for task := range taskCh {
					os.MkdirAll(filepath.Dir(task.path), 0755)
					ok := a.downloadFromMirrors([]string{task.url, strings.Replace(task.url, "piston-data.mojang.com", "bmclapi2.bangbang93.com", 1)}, task.path)
					if ok {
						// 下载后校验大小
						if info, err := os.Stat(task.path); err != nil || (task.size > 0 && info.Size() != task.size) {
							os.Remove(task.path)
							atomic.AddInt64(&failCount, 1)
						}
					} else {
						atomic.AddInt64(&failCount, 1)
					}
					done := atomic.AddInt64(&doneCount, 1)
					emitMu.Lock()
					if time.Since(lastEmit) > 300*time.Millisecond {
						lastEmit = time.Now()
						emitMu.Unlock()
						a.emitProgress("downloading", fmt.Sprintf("下载 Java %d/%d (%d%%)", done, total, done*100/total), done, total)
						continue
					}
					emitMu.Unlock()
				}
			}()
		}
		for _, task := range fileTasks {
			taskCh <- task
		}
		close(taskCh)
		wg.Wait()
	}

	if failCount > 0 {
		// 下载不完整，清理整个目录（同 PCL：防止残留只下了一半但 -version 能跑的 Java）
		os.RemoveAll(baseDir)
		return fmt.Errorf("Java 文件下载有 %d 个失败，已清理，请重试", failCount)
	}

	a.writeLog("Java %d 下载完成: %s", majorVer, baseDir)
	a.emitProgress("downloading", fmt.Sprintf("Java %d 安装完成", majorVer), total, total)
	return nil
}

// selectJavaForInstaller 选择适合运行加载器安装器的 Java（需要 Java 17+）
func (a *App) selectJavaForInstaller() (*JavaEntry, error) {
	javaList := a.SearchJava()

	// 优先选择 Java 17+（ForgeInstaller 需要）
	for _, j := range javaList {
		if j.MajorVer >= 17 {
			return &j, nil
		}
	}

	// 回退到 Java 8+（某些旧版安装器可能兼容）
	for _, j := range javaList {
		if j.MajorVer >= 8 {
			return &j, nil
		}
	}

	return nil, fmt.Errorf("未找到合适的 Java（需要 Java 17+，最低 Java 8）")
}

// GetRecommendedJavaForVersion 获取推荐安装的 Java 版本号（供前端提示用）
func (a *App) GetRecommendedJavaForVersion(versionID string) int {
	req := a.GetJavaRequirement(versionID)
	if req.MinMajor > 0 {
		return req.MinMajor
	}
	// 对于非常老的版本（MinMajor=0），推荐 Java 8（最兼容的版本）
	return 8
}
