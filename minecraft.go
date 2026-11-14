package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// launcherVersion 启动器版本号
const launcherVersion = "1.0.0-PR.4"

// GetLauncherVersion 获取启动器版本号（避免前端硬编码）
func (a *App) GetLauncherVersion() string {
	return launcherVersion
}

// ===== Win32 API 用于窗口检测 =====

var (
	user32DLL         = syscall.NewLazyDLL("user32.dll")
	kernel32DLL       = syscall.NewLazyDLL("kernel32.dll")
	procEnumWindows   = user32DLL.NewProc("EnumWindows")
	procGetClassName  = user32DLL.NewProc("GetClassNameA")
	procGetWindowText = user32DLL.NewProc("GetWindowTextA")
	procGetWindowPID  = user32DLL.NewProc("GetWindowThreadProcessId")
	procOpenProcess   = kernel32DLL.NewProc("OpenProcess")
	procGetProcessTimes = kernel32DLL.NewProc("GetProcessTimes")
	procCloseHandle   = kernel32DLL.NewProc("CloseHandle")
)

// MCVersion 表示一个 Minecraft 版本
type MCVersion struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	ReleaseTime string `json:"releaseTime"`
}

// VersionManifest 版本清单
type VersionManifest struct {
	Latest struct {
		Release  string `json:"release"`
		Snapshot string `json:"snapshot"`
	} `json:"latest"`
	Versions []MCVersionInfo `json:"versions"`
}

// MCVersionInfo 版本信息
type MCVersionInfo struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	ReleaseTime string `json:"releaseTime"`
}

// DownloadProgress 下载进度
type DownloadProgress struct {
	TotalBytes      int64   `json:"totalBytes"`
	DownloadedBytes int64   `json:"downloadedBytes"`
	Percentage      float64 `json:"percentage"`
	CurrentFile     string  `json:"currentFile"`
	Status          string  `json:"status"`
}

// DownloadItem 下载列表项
// DownloadItem 下载列表项
type DownloadItem struct {
	ID             string  `json:"id"`
	URL            string  `json:"url"`
	CustomName     string  `json:"customName"`
	Type           string  `json:"type"`
	ItemType       string  `json:"itemType"`       // "game", "java", "mod", "loader", "game+loader"
	JavaMajor      int     `json:"javaMajor"`      // Java 主版本号（仅 Java 类型）
	SavePath       string  `json:"savePath"`       // 保存路径（仅 Mod 类型）
	LoaderName     string  `json:"loaderName"`     // 加载器类型（仅 game+loader 类型）
	LoaderVersion  string  `json:"loaderVersion"`  // 加载器版本（仅 game+loader 类型）
	OptiFineType   string  `json:"optifineType"`   // OptiFine 类型（仅 game+loader 类型且选 OptiFine 时）
	OptiFinePatch  string  `json:"optifinePatch"`  // OptiFine Patch（仅 game+loader 类型且选 OptiFine 时）
	Status         string  `json:"status"`         // pending, downloading, completed, failed
	Progress       float64 `json:"progress"`
	CurrentStep    string  `json:"currentStep"`    // 当前步骤说明（下载原版/安装加载器/库文件/资源等）
	ErrorMsg       string  `json:"errorMsg"`       // 错误信息（仅 failed 状态）
}

// 版本 JSON 相关结构体

type VersionJSON struct {
	ID              string           `json:"id"`
	Type            string           `json:"type"`
	MainClass       string           `json:"mainClass"`
	MinecraftArgs   string           `json:"minecraftArguments"`
	Arguments       *ArgumentsObj    `json:"arguments"`
	Libraries       []Library        `json:"libraries"`
	Downloads       *VersionDownloads `json:"downloads"`
	AssetIndex      *AssetIndexRef   `json:"assetIndex"`
	ReleaseTime     string           `json:"releaseTime"`
	InheritsFrom    string           `json:"inheritsFrom"`
	Jar             string           `json:"jar"`
}

type ArgumentsObj struct {
	JVM  []interface{} `json:"jvm"`
	Game []interface{} `json:"game"`
}

type Library struct {
	Name      string            `json:"name"`
	Downloads *LibDownloads     `json:"downloads"`
	Natives   map[string]string `json:"natives"`
	Rules     []Rule            `json:"rules"`
	URL       string            `json:"url"`      // 有些库直接提供 URL
	JarPath   string            `json:"path"`      // 有些库直接提供 path（如 Forge 安装器解压的）
}

type LibDownloads struct {
	Artifact    *LibArtifact            `json:"artifact"`
	Classifiers map[string]*LibArtifact `json:"classifiers"`
}

type LibArtifact struct {
	Path string `json:"path"`
	URL  string `json:"url"`
	SHA1 string `json:"sha1"`
	Size int64  `json:"size"`
}

type Rule struct {
	Action string  `json:"action"`
	OS     *RuleOS `json:"os"`
}

type RuleOS struct {
	Name string `json:"name"`
}

type VersionDownloads struct {
	Client *LibArtifact `json:"client"`
	Server *LibArtifact `json:"server"`
}

type AssetIndexRef struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	SHA1      string `json:"sha1"`
	Size      int64  `json:"size"`
	TotalSize int64  `json:"totalSize"`
}

type AssetIndex struct {
	Objects map[string]AssetObject `json:"objects"`
}

type AssetObject struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

// getMinecraftDir 获取 .minecraft 目录
func (a *App) getMinecraftDir() string {
	return a.GetMinecraftDir()
}

// replaceWithBMCLAPI 将 Mojang URL 替换为 BMCLAPI 镜像
func replaceWithBMCLAPI(url string) string {
	url = strings.Replace(url, "https://piston-meta.mojang.com", "https://bmclapi2.bangbang93.com", 1)
	url = strings.Replace(url, "https://launcher.mojang.com", "https://bmclapi2.bangbang93.com", 1)
	url = strings.Replace(url, "https://libraries.minecraft.net", "https://bmclapi2.bangbang93.com/maven", 1)
	return url
}

// emitProgress 发送下载进度事件，同时更新下载列表中当前下载项的进度
// 高频下载时进行节流（100ms），避免事件风暴导致前端卡顿；终态（completed/failed）不节流
var lastProgressEmit time.Time

// setProgressScale 设置当前下载项的阶段进度映射：内部子进度 pct (0-100) 显示为 base + pct/100*span
// 用于把多个阶段（jar/库/资源/安装器运行等）组合成整项的总百分比，避免某阶段无进度时卡在 0%
func (a *App) setProgressScale(base, span float64) {
	a.progressBase = base
	a.progressSpan = span
}

// mapProgressToScale 将子进度映射到当前阶段区间
func (a *App) mapProgressToScale(pct float64) float64 {
	if a.progressSpan <= 0 {
		return pct
	}
	mapped := a.progressBase + pct/100*a.progressSpan
	if mapped > 100 {
		mapped = 100
	}
	return mapped
}

func (a *App) emitProgress(status string, currentFile string, downloaded, total int64) {
	// 节流：非终态且距上次发送不足 100ms 时跳过
	if status != "completed" && status != "failed" {
		if time.Since(lastProgressEmit) < 100*time.Millisecond {
			// 仍然更新内存中的进度，但不发事件
			var pct float64
			if total > 0 {
				pct = float64(downloaded) / float64(total) * 100
			}
			a.downloadMutex.Lock()
			for i := range a.downloadList {
				if a.downloadList[i].Status == "downloading" {
					a.downloadList[i].Progress = a.mapProgressToScale(pct)
					a.downloadList[i].CurrentStep = currentFile
					break
				}
			}
			a.downloadMutex.Unlock()
			return
		}
	}
	lastProgressEmit = time.Now()

	var pct float64
	if total > 0 {
		pct = float64(downloaded) / float64(total) * 100
	}
	a.downloadProgress = DownloadProgress{
		TotalBytes:      total,
		DownloadedBytes: downloaded,
		Percentage:      pct,
		CurrentFile:     currentFile,
		Status:          status,
	}

	// 更新下载列表中正在下载项的进度（映射到阶段区间）
	a.downloadMutex.Lock()
	for i := range a.downloadList {
		if a.downloadList[i].Status == "downloading" {
			a.downloadList[i].Progress = a.mapProgressToScale(pct)
			a.downloadList[i].CurrentStep = currentFile
			break
		}
	}
	a.downloadMutex.Unlock()

	runtime.EventsEmit(a.ctx, "downloadProgress", a.downloadProgress)
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
}

// emitFixProgress 启动补全阶段的进度上报：
// 除常规 downloadProgress（下载列表）外，同时发 launchFixProgress（启动界面遮罩显示步骤文本），
// 否则启动界面只会显示静态的"补全文件中..."，用户会以为卡死
func (a *App) emitFixProgress(step string, done, total int64) {
	a.emitProgress("downloading", step, done, total)
	runtime.EventsEmit(a.ctx, "launchFixProgress", step)
}

// formatBytesForProgress 将字节数格式化为 MB 显示（进度步骤文本用）
func formatBytesForProgress(b int64) string {
	return fmt.Sprintf("%.1f MB", float64(b)/1024/1024)
}

// downloadFileMultiThread 多线程分段下载单个文件（参考补全文件的并发思路）
// 通过 HTTP Range 将文件分成 threads 段并行下载；服务器不支持 Range 时自动回退单线程
// 进度通过 emitProgress 上报（文件名 + 已下载字节/总字节），total<=0 时步骤文本显示已下载量
func (a *App) downloadFileMultiThread(url string, destPath string, threads int) error {
	if threads < 1 {
		threads = 8
	}
	os.MkdirAll(filepath.Dir(destPath), 0755)

	// 已存在则跳过
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 {
		return nil
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败 %s: %v", url, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1")

	client := &http.Client{Timeout: 30 * time.Second}
	// 先发 HEAD/Range 探测：获取总大小与是否支持分段
	probe, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败 %s: %v", url, err)
	}
	if probe.StatusCode != http.StatusOK {
		probe.Body.Close()
		return fmt.Errorf("下载失败 %s: HTTP %d", url, probe.StatusCode)
	}
	total := probe.ContentLength
	acceptRanges := probe.Header.Get("Accept-Ranges")
	probe.Body.Close()

	name := filepath.Base(destPath)
	if total <= 0 || !strings.EqualFold(acceptRanges, "bytes") {
		// 服务器不支持分段或大小未知 → 单线程流式下载
		return a.downloadFileStream(url, destPath, name, total)
	}

	// 分段并行下载到临时文件，最后合并
	partDir := destPath + ".qglparts"
	os.RemoveAll(partDir)
	os.MkdirAll(partDir, 0755)
	defer os.RemoveAll(partDir)

	segmentSize := total / int64(threads)
	type segment struct {
		index int64
		start int64
		end   int64
	}
	segments := make([]segment, 0, threads)
	var start int64
	for i := 0; i < threads; i++ {
		end := start + segmentSize - 1
		if i == threads-1 {
			end = total - 1
		}
		if start > end {
			break
		}
		segments = append(segments, segment{index: int64(i), start: start, end: end})
		start = end + 1
	}

	var (
		wg        sync.WaitGroup
		downloaded int64
		mu        sync.Mutex
		firstErr  error
		lastEmit  time.Time
	)
	wg.Add(len(segments))
	for _, seg := range segments {
		seg := seg
		go func() {
			defer wg.Done()
			preq, err := http.NewRequest("GET", url, nil)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			preq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1")
			preq.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", seg.start, seg.end))

			resp, err := http.DefaultClient.Do(preq)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("HTTP %d", resp.StatusCode)
				}
				mu.Unlock()
				return
			}

			partPath := filepath.Join(partDir, fmt.Sprintf("%04d.part", seg.index))
			pf, err := os.Create(partPath)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			defer pf.Close()

			buf := make([]byte, 64*1024)
			for {
				n, readErr := resp.Body.Read(buf)
				if n > 0 {
					if _, werr := pf.Write(buf[:n]); werr != nil {
						mu.Lock()
						if firstErr == nil {
							firstErr = werr
						}
						mu.Unlock()
						return
					}
					atomic.AddInt64(&downloaded, int64(n))
					// 进度上报（加锁避免时间戳竞争，200ms 节流）
					mu.Lock()
					if time.Since(lastEmit) > 200*time.Millisecond {
						lastEmit = time.Now()
						dl := atomic.LoadInt64(&downloaded)
						mu.Unlock()
						a.emitProgress("downloading", fmt.Sprintf("%s %s/%s (%d%%)", name, formatBytesForProgress(dl), formatBytesForProgress(total), dl*100/total), dl, total)
						continue
					}
					mu.Unlock()
				}
				if readErr == io.EOF {
					return
				}
				if readErr != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = readErr
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return fmt.Errorf("下载失败 %s: %v", url, firstErr)
	}

	// 合并分段文件
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("创建文件失败 %s: %v", destPath, err)
	}
	defer out.Close()
	for _, seg := range segments {
		partPath := filepath.Join(partDir, fmt.Sprintf("%04d.part", seg.index))
		pf, err := os.Open(partPath)
		if err != nil {
			return fmt.Errorf("合并分段失败: %v", err)
		}
		_, err = io.Copy(out, pf)
		pf.Close()
		if err != nil {
			return fmt.Errorf("合并分段失败: %v", err)
		}
	}
	a.emitProgress("downloading", name, total, total)
	return nil
}

// downloadFileStream 单线程流式下载（多线程的回退路径），带进度
func (a *App) downloadFileStream(url string, destPath string, name string, total int64) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败 %s: %v", url, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败 %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败 %s: HTTP %d", url, resp.StatusCode)
	}
	if resp.ContentLength > 0 {
		total = resp.ContentLength
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("创建文件失败 %s: %v", destPath, err)
	}
	defer out.Close()

	var downloaded int64
	buf := make([]byte, 64*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
			downloaded += int64(n)
			if total > 0 {
				a.emitProgress("downloading", fmt.Sprintf("%s %s/%s (%d%%)", name, formatBytesForProgress(downloaded), formatBytesForProgress(total), downloaded*100/total), downloaded, total)
			} else {
				// 总大小未知（如 chunked 传输）：进度条保持 0，步骤文本显示已下载量
				a.emitProgress("downloading", fmt.Sprintf("%s %s", name, formatBytesForProgress(downloaded)), 0, 0)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return nil
}

// downloadFile 下载文件到指定路径
func (a *App) downloadFile(url string, destPath string, reportProgress bool) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败 %s: %v", dir, err)
	}

	// 如果文件已存在，跳过下载
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 {
		return nil
	}

	// 创建请求并添加 User-Agent（避免 BMCLAPI 403 拦截）
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败 %s: %v", url, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败 %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败 %s: HTTP %d", url, resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("创建文件失败 %s: %v", destPath, err)
	}
	defer out.Close()

	if reportProgress {
		total := resp.ContentLength
		var downloaded int64
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				_, werr := out.Write(buf[:n])
				if werr != nil {
					return werr
				}
				downloaded += int64(n)
				a.emitProgress("downloading", filepath.Base(destPath), downloaded, total)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
	} else {
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return fmt.Errorf("写入文件失败 %s: %v", destPath, err)
		}
	}

	return nil
}

// GetVersionManifest 获取版本清单，优先使用 BMCLAPI，失败回退 Mojang
func (a *App) GetVersionManifest() ([]MCVersion, error) {
	urls := []string{
		"https://bmclapi2.bangbang93.com/mc/game/version_manifest_v2.json",
		"https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
	}

	var body []byte
	var lastErr error

	for _, u := range urls {
		resp, err := http.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, u)
			continue
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		break
	}

	if lastErr != nil {
		return nil, fmt.Errorf("获取版本清单失败: %v", lastErr)
	}

	var manifest VersionManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("解析版本清单失败: %v", err)
	}

	var result []MCVersion
	for _, v := range manifest.Versions {
		if v.Type == "release" || v.Type == "snapshot" {
			result = append(result, MCVersion{
				ID:          v.ID,
				Type:        v.Type,
				URL:         v.URL,
				ReleaseTime: v.ReleaseTime,
			})
		}
	}

	return result, nil
}

// GetInstalledVersions 获取已安装的版本列表（仅读取，不扫描创建 config.json）
func (a *App) GetInstalledVersions() ([]InstalledVersionInfo, error) {
	mcDir := a.getMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []InstalledVersionInfo{}, nil
		}
		return nil, fmt.Errorf("读取版本目录失败: %v", err)
	}

	var installed []InstalledVersionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		versionFolder := filepath.Join(versionsDir, entry.Name())
		// 验证版本是否完整安装
		if !a.validateVersionInstallation(versionFolder) {
			continue
		}

		info := a.readVersionInfo(versionFolder, entry.Name())
		installed = append(installed, info)
	}

	return installed, nil
}

// ScanVersions 扫描所有版本文件夹，创建/更新 QGL/config.json，返回最新列表
func (a *App) ScanVersions() ([]InstalledVersionInfo, error) {
	mcDir := a.getMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []InstalledVersionInfo{}, nil
		}
		return nil, fmt.Errorf("读取版本目录失败: %v", err)
	}

	var installed []InstalledVersionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		versionFolder := filepath.Join(versionsDir, entry.Name())
		if !a.validateVersionInstallation(versionFolder) {
			continue
		}

		info := a.scanVersionFolder(versionFolder, entry.Name())
		installed = append(installed, info)
	}

	return installed, nil
}

// InstalledVersionInfo 安装版本的信息
type InstalledVersionInfo struct {
	FolderName string `json:"folderName"` // 文件夹名（用于启动）
	Name       string `json:"name"`       // 显示名（可能为空）
	Version    string `json:"version"`    // 游戏版本（如 1.12.2）
	Loader     string `json:"loader"`     // 加载器（forge/fabric/neoforge，可能为空）
	Type       string `json:"type"`       // 类型：game/loader/modpack
}

// readVersionInfo 仅读取 QGL/config.json，没有则返回基本信息（不创建）
func (a *App) readVersionInfo(versionFolder string, folderName string) InstalledVersionInfo {
	configPath := filepath.Join(versionFolder, "QGL", "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var config map[string]string
		if err := json.Unmarshal(data, &config); err == nil {
			return InstalledVersionInfo{
				FolderName: folderName,
				Name:       config["name"],
				Version:    config["version"],
				Loader:     config["loader"],
				Type:       config["type"],
			}
		}
	}
	// 没有 config.json，返回基本信息
	return InstalledVersionInfo{
		FolderName: folderName,
		Name:       "",
		Version:    folderName,
		Loader:     "",
		Type:       "game",
	}
}

// scanVersionFolder 扫描版本文件夹，解析版本 JSON，创建/更新 QGL/config.json
func (a *App) scanVersionFolder(versionFolder string, folderName string) InstalledVersionInfo {
	// 1. 尝试读取已有的 QGL/config.json
	configPath := filepath.Join(versionFolder, "QGL", "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var config map[string]string
		if err := json.Unmarshal(data, &config); err == nil {
			return InstalledVersionInfo{
				FolderName: folderName,
				Name:       config["name"],
				Version:    config["version"],
				Loader:     config["loader"],
				Type:       config["type"],
			}
		}
	}

	// 2. 没有 config.json，解析版本 JSON 创建
	versionJSON, err := a.resolveVersionJSON(folderName)
	if err != nil {
		// 解析失败，返回基本信息
		return InstalledVersionInfo{
			FolderName: folderName,
			Name:       "",
			Version:    folderName,
			Loader:     "",
			Type:       "game",
		}
	}

	// 读取原始 JSON 文本用于检测 loader
	jsonPath := filepath.Join(versionFolder, folderName+".json")
	if _, err := os.Stat(jsonPath); err != nil {
		jsonFiles, _ := filepath.Glob(filepath.Join(versionFolder, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		}
	}
	jsonText, _ := os.ReadFile(jsonPath)

	// 检测 loader（参考 PCL ModMinecraft.vb）
	loader := ""
	if strings.Contains(string(jsonText), "net.fabricmc:fabric-loader") {
		loader = "fabric"
	} else if strings.Contains(string(jsonText), "org.quiltmc:quilt-loader") {
		loader = "quilt"
	} else if strings.Contains(string(jsonText), "net.neoforge") {
		loader = "neoforge"
	} else if strings.Contains(string(jsonText), "minecraftforge") && !strings.Contains(string(jsonText), "net.neoforge") {
		loader = "forge"
	}

	// 确定游戏版本
	gameVersion := versionJSON.InheritsFrom
	if gameVersion == "" {
		gameVersion = versionJSON.ID
	}

	// 确定类型
	versionType := "game"
	if loader != "" {
		versionType = "loader"
	}

	info := InstalledVersionInfo{
		FolderName: folderName,
		Name:       "",
		Version:    gameVersion,
		Loader:     loader,
		Type:       versionType,
	}

	// 3. 创建 QGL/config.json
	configDir := filepath.Join(versionFolder, "QGL")
	if err := os.MkdirAll(configDir, 0755); err == nil {
		config := map[string]string{
			"type":    versionType,
			"name":    "",
			"version": gameVersion,
			"loader":  loader,
		}
		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0644)
	}

	return info
}

// ===== 下载列表功能 =====

// AddToDownloadList 添加版本到下载列表
func (a *App) AddToDownloadList(versionID string, versionURL string, customName string, versionType string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在同名版本: %s", customName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         versionID,
		URL:        versionURL,
		CustomName: customName,
		Type:       versionType,
		ItemType:   "game",
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// AddToDownloadListWithLoader 添加带加载器的游戏到下载列表
func (a *App) AddToDownloadListWithLoader(versionID string, versionURL string, customName string, versionType string, loaderName string, loaderVersion string, optifineType string, optifinePatch string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在同名版本: %s", customName)
		}
	}

	displayName := customName
	if loaderName != "" {
		displayName += " (" + loaderName + " " + loaderVersion + ")"
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:             versionID,
		URL:            versionURL,
		CustomName:     displayName,
		Type:           versionType,
		ItemType:       "game+loader",
		LoaderName:     loaderName,
		LoaderVersion:  loaderVersion,
		OptiFineType:   optifineType,
		OptiFinePatch:  optifinePatch,
		Status:         "pending",
		Progress:       0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// AddJavaToDownloadList 添加 Java 到下载列表
func (a *App) AddJavaToDownloadList(majorVer int) error {
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

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	customName := "Java " + fmt.Sprintf("%d", majorVer)
	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在: %s", customName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         fmt.Sprintf("java-%d", majorVer),
		URL:        target.URL,
		CustomName: customName,
		Type:       "java",
		ItemType:   "java",
		JavaMajor:  majorVer,
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// RemoveFromDownloadList 从下载列表移除
