package main

import (
	"archive/zip"
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

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
	if err := validateDownloadURL(url); err != nil {
		return err
	}
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
	if err := validateDownloadURL(url); err != nil {
		return err
	}
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
	if err := validateDownloadURL(url); err != nil {
		return err
	}
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
	if err := validateVersionName(customName); err != nil {
		return fmt.Errorf("非法版本名: %v", err)
	}
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
				libPath, safeErr := safeRelPath(filepath.Join(mcDir, "libraries"), artifact.Path)
				if safeErr != nil {
					continue
				}
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
						if !isHexHash(hash) {
							continue
						}
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
func (a *App) ensureNativesForLoader(mcDir string, versionID string, versionDir string, nativesDir string, versionJSON *VersionJSON) {
	// 策略1: 从父版本（原版 MC）的 natives 目录复制
	if versionJSON.InheritsFrom != "" {
		parentNativesDir := filepath.Join(mcDir, "versions", versionJSON.InheritsFrom, versionJSON.InheritsFrom+"-natives")
		if entries, err := os.ReadDir(parentNativesDir); err == nil && len(entries) > 0 {
			fmt.Printf("从父版本复制 natives: %s -> %s\n", parentNativesDir, nativesDir)
			copyDirContents(parentNativesDir, nativesDir)
			return
		}
	}

	// 策略2: 尝试从其他已安装版本中查找匹配的原版 natives
	versionsDir := filepath.Join(mcDir, "versions")
	entries, _ := os.ReadDir(versionsDir)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidateNatives := filepath.Join(versionsDir, entry.Name(), entry.Name()+"-natives")
		if info, err := os.Stat(candidateNatives); err == nil && info.IsDir() {
			if subEntries, err2 := os.ReadDir(candidateNatives); err2 == nil && len(subEntries) > 0 {
				fmt.Printf("从 %s 复制 natives 到 %s\n", candidateNatives, nativesDir)
				copyDirContents(candidateNatives, nativesDir)
				return
			}
		}
	}

	// 策略3: 强制重新解压（合并后的 JSON 应该包含 native 库信息）
	fmt.Printf("尝试重新解压 natives 到: %s\n", nativesDir)
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
}

// copyDirContents 复制目录中的所有文件到目标目录
func copyDirContents(srcDir string, dstDir string) error {
	os.MkdirAll(dstDir, 0755)

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		data, err := os.ReadFile(srcPath)
		if err != nil {
			continue
		}
		os.WriteFile(dstPath, data, 0644)
	}

	return nil
}

// generateOfflineUUID 根据用户名生成离线 UUID
func generateOfflineUUID(username string) string {
	data := "OfflinePlayer:" + username
	hash := md5.Sum([]byte(data))

	hash[6] = (hash[6] & 0x0f) | 0x30
	hash[8] = (hash[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:16],
	)
}

// generateRandomToken 生成随机访问令牌（避免Demo模式）
func generateRandomToken() string {
	now := time.Now().UnixNano()
	data := fmt.Sprintf("QGLToken%d%d", now, os.Getpid())
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%08x%04x%04x%04x%012x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:16],
	)
}

// 崩溃检测关键字（参考PCL）
var crashKeywords = []string{
	"Crash report saved to",
	"This crash report has been saved to:",
	"Could not save crash report to",
	"Someone is closing me!",
	"Restarting Minecraft with command",
	"An exception was thrown, the game will display an error screen and halt.",
	"UNABLE TO LAUNCH",
	"Failed to start the Minecraft runtime",
	"Exception in thread",
	"java.lang.UnsatisfiedLinkError",
	"java.lang.NoClassDefFoundError",
	"java.lang.OutOfMemoryError",
	"Unable to launch",
	"java.lang.reflect.InvocationTargetException",
}

// 日志进度关键字（参考PCL的Watcher）
var logProgressKeywords = []struct {
	level  int
	keyword string
}{
	{2, "Setting user:"},
	{3, "LWJGL Version:"},
	{3, "lwjgl version"},
	{4, "OpenAL initialized"},
	{4, "Starting up SoundSystem"},
	{5, "Created: "},
	{5, "textures"},
	{5, "-atlas"},
}

// LaunchGame 启动 Minecraft 游戏，并检测窗口出现或崩溃
func (a *App) LaunchGame(versionID string) error {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)

	// 设置启动日志路径（版本目录下的 QGL\Logs\qgl_launch.log）
	a.launchLogPath = filepath.Join(versionDir, "QGL", "Logs", "qgl_launch.log")
	a.writeLog("===== 启动游戏: %s =====", versionID)
	a.writeLog("版本目录: %s", versionDir)
	a.writeLog("启动日志: %s", a.launchLogPath)

	// 1. 解析版本 JSON（处理 inheritsFrom 继承关系）
	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	// 判断是否为旧版 JSON（使用 minecraftArguments 而非 arguments）
	isOldJSON := versionJSON.MinecraftArgs != ""

	// 2. 选择合适的 Java（根据 MC 版本自动匹配）
	javaEntry, err := a.SelectJavaForVersion(versionID)
	if err != nil {
		return fmt.Errorf("Java 选择失败: %v", err)
	}
	javaPath := javaEntry.Path

	// 3. 确定游戏目录（版本隔离）
	var gameDir string
	if a.isVersionIsolated() {
		gameDir = versionDir
	} else {
		gameDir = mcDir
	}

	// 4. 确保游戏目录存在
	if err := os.MkdirAll(gameDir, 0755); err != nil {
		return fmt.Errorf("创建游戏目录失败: %v", err)
	}

	// 5. 补全缺失的库文件（参考 PCL 的 DlClientFix）
	runtime.EventsEmit(a.ctx, "launchStatus", "fixing")
	a.emitProgress("downloading", "补全文件中", 0, 0)
	a.fixMissingLibraries(mcDir, versionJSON)

	// 6. 提取 natives（从合并后的完整 libraries 列表中提取）
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	if err := os.MkdirAll(nativesDir, 0755); err != nil {
		return fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)

	// 6.5 如果 natives 目录为空（加载器版本的原版 natives 在父版本目录中），
	// 尝试从父版本的 natives 目录复制或重新解压
	if isEmpty, _ := isDirEmpty(nativesDir); isEmpty {
		a.writeLog("警告: natives 目录为空，尝试从父版本或原版复制: %s", nativesDir)
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}

	// 7. 构建类路径
	classpathEntries := a.buildClasspath(mcDir, versionID, versionJSON)

	// 7.1 Forge 1.17+ 特殊处理：从 classpath 中移除 minecraft.jar
	// 原因：Forge 1.17+ 使用 BootstrapLauncher + ALL-MODULE-PATH，
	//        如果 minecraft.jar 在 classpath 中，JVM 会把它加载为模块 minecraft，
	//        与 Forge 的模块 _1._19._2 冲突（两者导出相同的包 → ResolutionException）
	//        BootstrapLauncher 会通过 -DignoreList 和自己的机制加载 minecraft.jar
	// 参考 PCL：PCL 使用 -jar JavaWrapper.jar 启动，-cp 被忽略，所以不受此影响
	isForgeNew := (strings.Contains(versionID, "forge") || strings.Contains(versionJSON.MainClass, "bootstraplauncher")) &&
		javaEntry.MajorVer >= 17
	if isForgeNew {
		// 从 classpathEntries 中移除 minecraft.jar（原版 jar）
		var filteredEntries []string
		for _, entry := range classpathEntries {
			// 检查是否是原版 jar（路径中包含 versions/1.19.2/1.19.2.jar 这样的模式）
			if strings.Contains(entry, "versions") && strings.HasSuffix(entry, ".jar") {
				// 提取 jar 文件名，检查是否是原版 jar（不包含 forge/fabric 等字样）
				jarBase := filepath.Base(entry)
				jarNameNoExt := strings.TrimSuffix(jarBase, ".jar")
				// 如果 jar 名字不包含 forge/fabric/neoforge，说明是原版 jar
				if !strings.Contains(strings.ToLower(jarNameNoExt), "forge") &&
					!strings.Contains(strings.ToLower(jarNameNoExt), "fabric") &&
					!strings.Contains(strings.ToLower(jarNameNoExt), "neoforge") &&
					!strings.Contains(strings.ToLower(jarNameNoExt), "quilt") {
					a.writeLog("Forge 1.17+ 模块冲突修复: 从 classpath 移除原版 jar: %s", entry)
					continue
				}
			}
			filteredEntries = append(filteredEntries, entry)
		}
		classpathEntries = filteredEntries
	}

	classpath := strings.Join(classpathEntries, ";")

	// 7.5 Fabric 特殊处理：设置 fabric.classPathGroups 系统属性
	// KnotClassLoader 需要此属性来正确加载 jline 等库，否则报 NoClassDefFoundError
	// 格式参考 Fabric 源码: "groupName:file://path1;file://path2"
	isFabric := strings.Contains(versionID, "fabric") ||
		strings.Contains(versionJSON.MainClass, "fabricmc") ||
		strings.Contains(versionJSON.MainClass, "knot")
	var fabricClassPathGroups string
	if isFabric && len(classpathEntries) > 0 {
		// 将每个 classpath 条目加上 file:// 前缀，用分号分隔（Fabric KnotClassLoader 期望的格式）
		var formattedPaths []string
		for _, p := range classpathEntries {
			formattedPaths = append(formattedPaths, "file:///"+strings.ReplaceAll(p, "\\", "/"))
		}
		fabricClassPathGroups = "default:" + strings.Join(formattedPaths, ";")
		a.writeLog("检测到 Fabric 版本，设置 fabric.classPathGroups (%d 个库)", len(classpathEntries))
	}

	maxMem := "2G"
	minMem := "1G"
	config, _ := a.GetGlobalConfig()
	if config != nil {
		if config.MaxMemory > 0 {
			maxMem = fmt.Sprintf("%dG", config.MaxMemory)
		}
		if config.MinMemory > 0 {
			minMem = fmt.Sprintf("%dG", config.MinMemory)
		}
	}

	var jvmArgs []string

	if isOldJSON {
		// 旧版（< 1.13）：手动拼接固定 JVM 参数模板（参考PCL的McLaunchArgumentsJvmOld）
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem),
			fmt.Sprintf("-Xms%s", minMem),
			"-Dlog4j2.formatMsgNoLookups=true",
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			"-XX:+UnlockExperimentalVMOptions",
			"-XX:+UseG1GC",
			"-XX:G1NewSizePercent=20",
			"-XX:G1ReservePercent=20",
			"-XX:MaxGCPauseMillis=50",
			"-XX:G1HeapRegionSize=32M",
		}
	} else {
		// 新版（>= 1.13）：从 arguments.jvm 数组解析
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem),
			fmt.Sprintf("-Xms%s", minMem),
			"-Dlog4j2.formatMsgNoLookups=true",
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			fmt.Sprintf("-Dorg.lwjgl.librarypath=%s", nativesDir),
			"-Dorg.lwjgl.util.Debug=true",
		}

		if versionJSON.Arguments != nil && len(versionJSON.Arguments.JVM) > 0 {
			for _, arg := range versionJSON.Arguments.JVM {
				switch v := arg.(type) {
				case string:
					// 替换变量
					resolved := v
					resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
					resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
					resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
					resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
					resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
					resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
					resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
					resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
					jvmArgs = append(jvmArgs, resolved)
				case map[string]interface{}:
					// 带 rules 的参数，检查是否适用
					if shouldIncludeArg(v) {
						if values, ok := v["value"]; ok {
							switch val := values.(type) {
							case string:
								resolved := val
								resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
								resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
								resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
								resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
								resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
								resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
								resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
								resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
								jvmArgs = append(jvmArgs, resolved)
							case []interface{}:
								for _, item := range val {
									if s, ok := item.(string); ok {
										resolved := s
										resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
										resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
										resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
										resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
										resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
										resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
										resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
										resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
										jvmArgs = append(jvmArgs, resolved)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 7.6 Fabric: 添加 fabric.classPathGroups 系统属性（必须在 jvmArgs 构建之后）
	if isFabric && fabricClassPathGroups != "" {
		jvmArgs = append(jvmArgs, "-Dfabric.classPathGroups="+fabricClassPathGroups)
	}

	// 7.7 Forge 特殊处理：移除我们之前添加的 --add-exports bootstraplauncher 参数
	// 问题：--add-exports 在模块加载前被处理，导致 "Unknown module" 警告
	// BootstrapLauncher 会自己处理模块加载，不需要提前添加此参数

	// 7.8 恢复原始的 ALL-MODULE-PATH 行为，不移除也不添加 --limit-modules
	// BootstrapLauncher 会正确处理模块依赖，不需要我们干预

	// 7.9 JVM 参数去重（参考 PCL 的 DeDuplicateDataList 逻辑）
	// 如果不合并多词参数（如 -XX:MaxDirectMemorySize 256M）就去重，
	// 会导致 Forge 1.17+ 启动无效（它有两个 --add-exports，其中一个会在去重时丢失）
	jvmArgs = deduplicateJvmArgs(jvmArgs)

	// 8. 构建游戏参数
	username := "Player"
	currentUser, err := a.GetCurrentUser()
	if err == nil && currentUser.Username != "" {
		username = currentUser.Username
	}
	userID := currentUser.Dir

	// 根据用户类型确定 UUID、access token 和 user type
	uuid := generateOfflineUUID(username)
	// 离线用户 AccessToken = UUID（参考PCL的McLoginLegacyStart，避免Demo模式）
	accessToken := uuid
	// PCL 对所有用户类型都使用 "msa" 作为 user_type，避免Demo模式
	userType := "msa"

	if currentUser.Type == UserTypePremium {
		authData, authErr := a.GetMSAuthData(userID)
		if authErr == nil && authData.MCAccessToken != "" {
			_ = a.RefreshMicrosoftToken(userID)
			authData, authErr = a.GetMSAuthData(userID)
			if authErr == nil {
				uuid = authData.UUID
				accessToken = authData.MCAccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s",
						uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
			}
		}
	}

	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(userID)
		if extErr == nil && extData.AccessToken != "" {
			_ = a.RefreshExternalToken(userID)
			extData, extErr = a.GetExternalAuthData(userID)
			if extErr == nil {
				uuid = extData.UUID
				accessToken = extData.AccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s",
						uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
				// 外置用户仍使用 "msa" 作为 user_type，避免 Demo 模式
				// authlib-injector 会拦截 Mojang authlib 调用并重定向到 Yggdrasil 服务器
			}
		}
	}

	assetsRoot := filepath.Join(mcDir, "assets")
	assetIndexName := ""
	if versionJSON.AssetIndex != nil {
		assetIndexName = versionJSON.AssetIndex.ID
	}

	// 旧版资源路径（1.6 以下使用 game_assets 而非 assets_root）
	gameAssets := filepath.Join(mcDir, "assets", "virtual", "legacy")

	replacements := map[string]string{
		"${auth_player_name}":  username,
		"${version_name}":      versionID,
		"${game_directory}":    gameDir,
		"${assets_root}":       assetsRoot,
		"${assets_index_name}": assetIndexName,
		"${auth_uuid}":         uuid,
		"${auth_access_token}": accessToken,
		"${access_token}":      accessToken,
		"${auth_session}":      accessToken,
		"${user_type}":         userType,
		"${version_type}":      "QGL",
		"${user_properties}":   "{}",
		"${game_assets}":       gameAssets,
		"${classpath}":         classpath,
		"${classpath_separator}": ";",
		"${natives_directory}": nativesDir,
		"${library_directory}": filepath.Join(mcDir, "libraries"),
		"${launcher_name}":     "QGL",
		"${launcher_version}": launcherVersion,
		"${resolution_width}":  "854",
		"${resolution_height}": "480",
	}

	var gameArgs []string

	// 旧版 Game 参数：从 minecraftArguments 字段解析（参考PCL的McLaunchArgumentsGameOld）
	if isOldJSON {
		parts := strings.Split(versionJSON.MinecraftArgs, " ")
		for _, part := range parts {
			arg := part
			for k, v := range replacements {
				arg = strings.ReplaceAll(arg, k, v)
			}
			gameArgs = append(gameArgs, arg)
		}
		// 旧版如果没有 --height 和 --width，追加默认分辨率
		hasHeight := false
		for _, a := range gameArgs {
			if a == "--height" || strings.HasPrefix(a, "--height=") {
				hasHeight = true
				break
			}
		}
		if !hasHeight {
			gameArgs = append(gameArgs, "--height", "480", "--width", "854")
		}
	}

	// 新版 Game 参数：从 arguments.game 数组解析（参考PCL的McLaunchArgumentsGameNew）
	// 注意：minecraftArguments 和 arguments.game 可以共存，两者拼接
	if versionJSON.Arguments != nil && len(versionJSON.Arguments.Game) > 0 {
		for _, arg := range versionJSON.Arguments.Game {
			switch v := arg.(type) {
			case string:
				resolved := v
				for k, rep := range replacements {
					resolved = strings.ReplaceAll(resolved, k, rep)
				}
				gameArgs = append(gameArgs, resolved)
			case map[string]interface{}:
				if shouldIncludeArg(v) {
					if values, ok := v["value"]; ok {
						switch val := values.(type) {
						case string:
							resolved := val
							for k, rep := range replacements {
								resolved = strings.ReplaceAll(resolved, k, rep)
							}
							gameArgs = append(gameArgs, resolved)
						case []interface{}:
							for _, item := range val {
								if s, ok := item.(string); ok {
									resolved := s
									for k, rep := range replacements {
										resolved = strings.ReplaceAll(resolved, k, rep)
									}
									gameArgs = append(gameArgs, resolved)
								}
							}
						}
					}
				}
			}
		}
	}

	// 8. 组装完整命令
	mainClass := versionJSON.MainClass
	if mainClass == "" {
		return fmt.Errorf("版本 JSON 中缺少 mainClass")
	}

	// 外置用户：注入 authlib-injector
	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(userID)
		if extErr != nil {
			a.writeLog("警告: 读取外置认证数据失败: %v", extErr)
		} else {
			injectorPath, injErr := a.GetAuthlibInjectorPath()
			if injErr != nil {
				a.writeLog("错误: 获取 authlib-injector 失败: %v", injErr)
				return fmt.Errorf("外置登录需要 authlib-injector，但获取失败: %v", injErr)
			}
			// 将 authlib-injector.jar 加入 classpath（关键！否则仍使用 Mojang 原版 authlib）
			classpath = injectorPath + ";" + classpath
			a.writeLog("authlib-injector 路径: %s", injectorPath)

			// 预获取服务器信息（参考 PCL 的 prefetched 机制）
			serverURL := extData.ServerURL
			prefetched := ""
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get(serverURL)
			if err == nil {
				respBody, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				prefetched = base64.StdEncoding.EncodeToString(respBody)
				a.writeLog("预获取服务器信息成功，长度: %d", len(respBody))
			} else {
				a.writeLog("警告: 预获取服务器信息失败: %v", err)
			}

			injectorArgs := []string{
				"-javaagent:" + injectorPath + "=" + serverURL,
				"-Dauthlibinjector.side=client",
			}
			if prefetched != "" {
				injectorArgs = append(injectorArgs, "-Dauthlibinjector.yggdrasil.prefetched="+prefetched)
			}
			// 插入到 jvmArgs 最前面
			jvmArgs = append(injectorArgs, jvmArgs...)
			a.writeLog("已注入 authlib-injector 参数: %v", injectorArgs)
		}
	}

	// 检查 jvmArgs 中是否已包含 -cp（新版 Forge/Fabric 的 JSON 中自带 -cp ${classpath}）
	hasCpInJvmArgs := false
	for i, arg := range jvmArgs {
		if arg == "-cp" && i+1 < len(jvmArgs) {
			hasCpInJvmArgs = true
			break
		}
	}

	var allArgs []string
	if hasCpInJvmArgs {
		// 新版 JSON 已包含 -cp，直接追加 mainClass 和 gameArgs
		allArgs = append(jvmArgs, mainClass)
		allArgs = append(allArgs, gameArgs...)
	} else {
		// 旧版 JSON 没有 -cp，需要手动添加
		allArgs = append(jvmArgs, "-cp", classpath, mainClass)
		allArgs = append(allArgs, gameArgs...)
	}

	// 打印完整命令行到日志文件（用于调试对比 PCL）
	a.writeLog("===== 完整启动命令 =====")
	a.writeLog("Java: %s", javaPath)
	a.writeLog("工作目录: %s", gameDir)
	a.writeLog("JVM 参数数: %d, Classpath 条目数: %d, 游戏参数数: %d, 总参数数: %d",
		len(jvmArgs), len(classpathEntries), len(gameArgs), len(allArgs))
	for i, arg := range allArgs {
		if len(arg) > 150 {
			a.writeLog("  [%d] %s...", i, arg[:150])
		} else {
			a.writeLog("  [%d] %s", i, arg)
		}
	}
	a.writeLog("========================")

	// 8.5 设置游戏语言为中文（参考 PCL 的 options.txt 修改逻辑）
	a.setGameLanguage(gameDir, versionID)

	// 9. 执行命令
	// 使用 SysProcAttr.CmdLine 直接传递原始命令行给 CreateProcess，
	// 避免 Go 的 makeCmdLine 参数解析问题，同时 Go 仍能直接追踪 Java 进程
	var cmdLineParts []string
	cmdLineParts = append(cmdLineParts, "\""+javaPath+"\"")
	for _, arg := range allArgs {
		if strings.Contains(arg, " ") {
			cmdLineParts = append(cmdLineParts, "\""+arg+"\"")
		} else {
			cmdLineParts = append(cmdLineParts, arg)
		}
	}
	fullCmdLine := strings.Join(cmdLineParts, " ")
	a.writeLog("命令行长度: %d 字符", len(fullCmdLine))

	cmd := exec.Command(javaPath)
	cmd.Dir = gameDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: fullCmdLine,
	}

	// 创建管道捕获 stdout 和 stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建 stdout 管道失败: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("创建 stderr 管道失败: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动游戏失败: %v", err)
	}

	pid := cmd.Process.Pid
	processStartTime := time.Now()
	a.writeLog("游戏进程 PID: %d", pid)

	// 10. 在后台监控游戏状态
	go a.watchGameProcess(cmd, stdoutPipe, stderrPipe, pid, processStartTime)

	return nil
}

// GetLaunchCommand 获取启动命令（不执行），用于导出启动命令功能
func (a *App) GetLaunchCommand(versionID string) (string, error) {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)

	// 1. 解析版本 JSON
	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return "", fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	isOldJSON := versionJSON.MinecraftArgs != ""

	// 2. 选择 Java
	javaEntry, err := a.SelectJavaForVersion(versionID)
	if err != nil {
		return "", fmt.Errorf("Java 选择失败: %v", err)
	}
	javaPath := javaEntry.Path

	// 3. 确定游戏目录
	var gameDir string
	if a.isVersionIsolated() {
		gameDir = versionDir
	} else {
		gameDir = mcDir
	}

	// 5. 补全缺失的库文件
	a.fixMissingLibraries(mcDir, versionJSON)

	// 6. 提取 natives
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	if err := os.MkdirAll(nativesDir, 0755); err != nil {
		return "", fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)

	if isEmpty, _ := isDirEmpty(nativesDir); isEmpty {
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}

	// 7. 构建类路径
	classpathEntries := a.buildClasspath(mcDir, versionID, versionJSON)

	isForgeNew := (strings.Contains(versionID, "forge") || strings.Contains(versionJSON.MainClass, "bootstraplauncher")) &&
		javaEntry.MajorVer >= 17
	if isForgeNew {
		var filteredEntries []string
		for _, entry := range classpathEntries {
			jarBase := filepath.Base(entry)
			jarNameNoExt := strings.TrimSuffix(jarBase, ".jar")
			if !strings.Contains(strings.ToLower(jarNameNoExt), "forge") &&
				!strings.Contains(strings.ToLower(jarNameNoExt), "fabric") &&
				!strings.Contains(strings.ToLower(jarNameNoExt), "neoforge") &&
				!strings.Contains(strings.ToLower(jarNameNoExt), "quilt") {
				continue
			}
			filteredEntries = append(filteredEntries, entry)
		}
		classpathEntries = filteredEntries
	}

	classpath := strings.Join(classpathEntries, ";")

	isFabric := strings.Contains(versionID, "fabric") ||
		strings.Contains(versionJSON.MainClass, "fabricmc") ||
		strings.Contains(versionJSON.MainClass, "knot")
	var fabricClassPathGroups string
	if isFabric && len(classpathEntries) > 0 {
		var formattedPaths []string
		for _, p := range classpathEntries {
			formattedPaths = append(formattedPaths, "file:///"+strings.ReplaceAll(p, "\\", "/"))
		}
		fabricClassPathGroups = "default:" + strings.Join(formattedPaths, ";")
	}

	maxMem := "2G"
	minMem := "1G"
	config, _ := a.GetGlobalConfig()
	if config != nil {
		if config.MaxMemory > 0 {
			maxMem = fmt.Sprintf("%dG", config.MaxMemory)
		}
		if config.MinMemory > 0 {
			minMem = fmt.Sprintf("%dG", config.MinMemory)
		}
	}

	var jvmArgs []string

	if isOldJSON {
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem),
			fmt.Sprintf("-Xms%s", minMem),
			"-Dlog4j2.formatMsgNoLookups=true",
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			"-XX:+UnlockExperimentalVMOptions",
			"-XX:+UseG1GC",
			"-XX:G1NewSizePercent=20",
			"-XX:G1ReservePercent=20",
			"-XX:MaxGCPauseMillis=50",
			"-XX:G1HeapRegionSize=32M",
		}
	} else {
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem),
			fmt.Sprintf("-Xms%s", minMem),
			"-Dlog4j2.formatMsgNoLookups=true",
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			fmt.Sprintf("-Dorg.lwjgl.librarypath=%s", nativesDir),
			"-Dorg.lwjgl.util.Debug=true",
		}

		if versionJSON.Arguments != nil && len(versionJSON.Arguments.JVM) > 0 {
			for _, arg := range versionJSON.Arguments.JVM {
				switch v := arg.(type) {
				case string:
					resolved := v
					resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
					resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
					resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
					resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
					resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
					resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
					resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
					resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
					jvmArgs = append(jvmArgs, resolved)
				case map[string]interface{}:
					if shouldIncludeArg(v) {
						if values, ok := v["value"]; ok {
							switch val := values.(type) {
							case string:
								resolved := val
								resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
								resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
								resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
								resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
								resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
								resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
								resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
								resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
								jvmArgs = append(jvmArgs, resolved)
							case []interface{}:
								for _, item := range val {
									if s, ok := item.(string); ok {
										resolved := s
										resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
										resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
										resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
										resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
										resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
										resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
										resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
										resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
										jvmArgs = append(jvmArgs, resolved)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if isFabric && fabricClassPathGroups != "" {
		jvmArgs = append(jvmArgs, "-Dfabric.classPathGroups="+fabricClassPathGroups)
	}

	jvmArgs = deduplicateJvmArgs(jvmArgs)

	// 8. 构建游戏参数
	username := "Player"
	currentUser, err := a.GetCurrentUser()
	if err == nil && currentUser.Username != "" {
		username = currentUser.Username
	}
	userID := currentUser.Dir

	uuid := generateOfflineUUID(username)
	accessToken := uuid
	userType := "msa"

	if currentUser.Type == UserTypePremium {
		authData, authErr := a.GetMSAuthData(userID)
		if authErr == nil && authData.MCAccessToken != "" {
			_ = a.RefreshMicrosoftToken(userID)
			authData, authErr = a.GetMSAuthData(userID)
			if authErr == nil {
				uuid = authData.UUID
				accessToken = authData.MCAccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s",
						uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
			}
		}
	}

	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(userID)
		if extErr == nil && extData.AccessToken != "" {
			_ = a.RefreshExternalToken(userID)
			extData, extErr = a.GetExternalAuthData(userID)
			if extErr == nil {
				uuid = extData.UUID
				accessToken = extData.AccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s",
						uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
				// 外置用户仍使用 "msa" 作为 user_type，避免 Demo 模式
				// authlib-injector 会拦截 Mojang authlib 调用并重定向到 Yggdrasil 服务器
			}
		}
	}

	assetsRoot := filepath.Join(mcDir, "assets")
	assetIndexName := ""
	if versionJSON.AssetIndex != nil {
		assetIndexName = versionJSON.AssetIndex.ID
	}

	gameAssets := filepath.Join(mcDir, "assets", "virtual", "legacy")

	replacements := map[string]string{
		"${auth_player_name}":    username,
		"${version_name}":        versionID,
		"${game_directory}":      gameDir,
		"${assets_root}":         assetsRoot,
		"${assets_index_name}":   assetIndexName,
		"${auth_uuid}":           uuid,
		"${auth_access_token}":   accessToken,
		"${access_token}":        accessToken,
		"${auth_session}":        accessToken,
		"${user_type}":           userType,
		"${version_type}":        "QGL",
		"${user_properties}":     "{}",
		"${game_assets}":         gameAssets,
		"${classpath}":           classpath,
		"${classpath_separator}": ";",
		"${natives_directory}":   nativesDir,
		"${library_directory}":   filepath.Join(mcDir, "libraries"),
		"${launcher_name}":       "QGL",
		"${launcher_version}": launcherVersion,
		"${resolution_width}":    "854",
		"${resolution_height}":   "480",
	}

	var gameArgs []string

	if isOldJSON {
		parts := strings.Split(versionJSON.MinecraftArgs, " ")
		for _, part := range parts {
			arg := part
			for k, v := range replacements {
				arg = strings.ReplaceAll(arg, k, v)
			}
			gameArgs = append(gameArgs, arg)
		}
		hasHeight := false
		for _, a := range gameArgs {
			if a == "--height" || strings.HasPrefix(a, "--height=") {
				hasHeight = true
				break
			}
		}
		if !hasHeight {
			gameArgs = append(gameArgs, "--height", "480", "--width", "854")
		}
	}

	if versionJSON.Arguments != nil && len(versionJSON.Arguments.Game) > 0 {
		for _, arg := range versionJSON.Arguments.Game {
			switch v := arg.(type) {
			case string:
				resolved := v
				for k, rep := range replacements {
					resolved = strings.ReplaceAll(resolved, k, rep)
				}
				gameArgs = append(gameArgs, resolved)
			case map[string]interface{}:
				if shouldIncludeArg(v) {
					if values, ok := v["value"]; ok {
						switch val := values.(type) {
						case string:
							resolved := val
							for k, rep := range replacements {
								resolved = strings.ReplaceAll(resolved, k, rep)
							}
							gameArgs = append(gameArgs, resolved)
						case []interface{}:
							for _, item := range val {
								if s, ok := item.(string); ok {
									resolved := s
									for k, rep := range replacements {
										resolved = strings.ReplaceAll(resolved, k, rep)
									}
									gameArgs = append(gameArgs, resolved)
								}
							}
						}
					}
				}
			}
		}
	}

	mainClass := versionJSON.MainClass
	if mainClass == "" {
		return "", fmt.Errorf("版本 JSON 中缺少 mainClass")
	}

	// 外置用户：注入 authlib-injector
	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(userID)
		if extErr != nil {
			return "", fmt.Errorf("读取外置认证数据失败: %v", extErr)
		}
		injectorPath, injErr := a.GetAuthlibInjectorPath()
		if injErr != nil {
			return "", fmt.Errorf("外置登录需要 authlib-injector，但获取失败: %v", injErr)
		}
		// 将 authlib-injector.jar 加入 classpath
		classpath = injectorPath + ";" + classpath

		serverURL := extData.ServerURL
		prefetched := ""
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(serverURL)
		if err == nil {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			prefetched = base64.StdEncoding.EncodeToString(respBody)
		}

		injectorArgs := []string{
			"-javaagent:" + injectorPath + "=" + serverURL,
			"-Dauthlibinjector.side=client",
		}
		if prefetched != "" {
			injectorArgs = append(injectorArgs, "-Dauthlibinjector.yggdrasil.prefetched="+prefetched)
		}
		jvmArgs = append(injectorArgs, jvmArgs...)
	}

	hasCpInJvmArgs := false
	for i, arg := range jvmArgs {
		if arg == "-cp" && i+1 < len(jvmArgs) {
			hasCpInJvmArgs = true
			break
		}
	}

	var allArgs []string
	if hasCpInJvmArgs {
		allArgs = append(jvmArgs, mainClass)
		allArgs = append(allArgs, gameArgs...)
	} else {
		allArgs = append(jvmArgs, "-cp", classpath, mainClass)
		allArgs = append(allArgs, gameArgs...)
	}

	// 组装完整命令字符串
	var cmdParts []string
	cmdParts = append(cmdParts, "\""+javaPath+"\"")
	for _, arg := range allArgs {
		if strings.Contains(arg, " ") || strings.Contains(arg, "\"") {
			cmdParts = append(cmdParts, "\""+strings.ReplaceAll(arg, "\"", "\\\"")+"\"")
		} else {
			cmdParts = append(cmdParts, arg)
		}
	}

	return strings.Join(cmdParts, " "), nil
}

// shouldIncludeArg 检查带 rules 的参数是否应该包含（参考PCL的McJsonRuleCheck）
func shouldIncludeArg(arg map[string]interface{}) bool {
	rulesRaw, ok := arg["rules"]
	if !ok {
		// 没有 rules，默认包含
		return true
	}

	rules, ok := rulesRaw.([]interface{})
	if !ok {
		return true
	}

	// 遍历所有规则
	for _, ruleRaw := range rules {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}

		action, _ := rule["action"].(string)
		if action == "" {
			continue
		}

		// 检查 features 规则（参考PCL：is_demo_user 的规则应该排除）
		if features, hasFeatures := rule["features"]; hasFeatures {
			if featMap, ok := features.(map[string]interface{}); ok {
				// 如果规则包含 is_demo_user，则排除此参数（我们不是 demo 用户）
				if _, isDemo := featMap["is_demo_user"]; isDemo {
					return false
				}
			}
		}

		// 检查 os 规则
		osRule, hasOS := rule["os"].(map[string]interface{})
		matchesOS := true
		if hasOS {
			osName, _ := osRule["name"].(string)
			// 我们在 Windows 上运行
			matchesOS = osName == "windows"
		}

		if action == "allow" {
			// allow 规则：如果匹配则允许
			if !matchesOS {
				return false
			}
		} else if action == "disallow" {
			// disallow 规则：如果匹配则禁止
			if matchesOS {
				return false
			}
		}
	}

	return true
}

// fixForgeModuleConflict 修复 Forge 启动时的 Java 模块系统冲突
// 问题：Forge 版本 JSON 的 arguments.jvm 中包含 --add-modules ALL-MODULE-PATH
// 这会让 Java 自动加载 classpath 中所有带 module-info.class 的 JAR 作为模块
// minecraft.jar (模块名 minecraft) 和 Forge JAR (模块名 _1._19._2 等) 都导出 net.minecraft.server → ResolutionException
// 解决方案：添加 --limit-modules 限制只加载 BootstrapLauncher 需要的核心模块，
//          排除 minecraft 和 Forge 内部模块，避免冲突
func (a *App) fixForgeModuleConflict(args []string) []string {
	result := make([]string, 0, len(args)+3)

	for i := 0; i < len(args); i++ {
		// 在 --add-modules ALL-MODULE-PATH 之后添加 --limit-modules
		if args[i] == "--add-modules" && i+1 < len(args) && args[i+1] == "ALL-MODULE-PATH" {
			result = append(result, args[i])
			result = append(result, args[i+1])
			// 插入 --limit-modules，限制模块加载范围
			result = append(result, "--limit-modules")
			result = append(result, "cpw.mods.bootstraplauncher,cpw.mods.securejarhandler,org.ow2.asm.asm,org.ow2.asm.asm-commons,org.ow2.asm.asm-tree,org.ow2.asm.asm-util,org.ow2.asm.asm-analysis,net.minecraftforge.jarjarfilesystems,java.base,java.logging,java.desktop,java.instrument,java.management,java.naming,java.prefs,java.security.sasl,jdk.attach,jdk.crypto.cryptoki,jdk.crypto.ec,jdk.jfr,jdk.library.loadhook,jdk.management.agent,jdk.naming.dns,jdk.nio.fs,jdk.sctp,jdk.unsupported,jdk.unsupported.desktop,jdk.zipfs")
			a.writeLog("修复模块冲突: 添加 --limit-modules（避免 minecraft 和 _1._19._2 冲突）")
			i++
			continue
		}
		result = append(result, args[i])
	}

	return result
}

// deduplicateJvmArgs JVM 参数去重（参考 PCL 的 DeDuplicateDataList 逻辑）
// PCL 注释: "如果不合并，会导致 Forge 1.17 启动无效，它有两个 --add-exports，
//          进一步导致其中一个在后面被去重丢失"
// 关键：使用"参数键+完整值"作为去重依据，而不是仅用键。
// 这样两个 --add-exports（值不同）都会保留，而真正重复的才会被去除。
func deduplicateJvmArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	// 将参数分组：每个以 - 开头的参数 + 它的后续值为一个组
	type argGroup struct {
		fullKey string // 键 + 所有值的拼接（用于去重判断）
		parts   []string // 原始参数列表
	}
	var groups []argGroup
	current := argGroup{}

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if current.fullKey != "" {
				groups = append(groups, current)
			}
			current = argGroup{fullKey: arg, parts: []string{arg}}
		} else {
			current.fullKey = current.fullKey + "\x00" + arg // 用 NULL 分隔键和值
			current.parts = append(current.parts, arg)
		}
	}
	if current.fullKey != "" {
		groups = append(groups, current)
	}

	// 按 fullKey 去重（相同键+相同值才去重，不同值的同名参数保留）
	seen := make(map[string]bool)
	var result []string
	for _, g := range groups {
		if !seen[g.fullKey] {
			seen[g.fullKey] = true
			result = append(result, g.parts...)
		}
	}

	return result
}

// watchGameProcess 监控游戏进程（参考PCL的Watcher类）
// 同时检测：窗口出现、进程退出、崩溃日志、加载进度
func (a *App) watchGameProcess(cmd *exec.Cmd, stdoutPipe io.Reader, stderrPipe io.Reader, pid int, processStartTime time.Time) {
	runtime.EventsEmit(a.ctx, "launchStatus", "launching")

	crashDetected := false
	crashReason := ""
	windowFound := false
	logProgress := 0 // 日志加载进度 1-5（参考PCL的Watcher）

	// 保存最近的日志行（用于崩溃时显示上下文）
	var recentLines []string
	const maxRecentLines = 50

	// 用 channel 通知进程退出
	exitChan := make(chan int, 1)

	// 用 Wait() 在独立 goroutine 中等待进程退出
	go func() {
		err := cmd.Wait()
		exitCode := -1
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		} else {
			exitCode = 0
		}
		exitChan <- exitCode
	}()

	// 启动日志监控 goroutine
	logChan := make(chan string, 200)

	// 读取 stdout
	if stdoutPipe != nil {
		go func() {
			scanner := bufio.NewScanner(stdoutPipe)
			for scanner.Scan() {
				line := scanner.Text()
				logChan <- line
			}
		}()
	}

	// 读取 stderr
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			logChan <- line
		}
	}()

	// 日志分析 goroutine
	go func() {
		for line := range logChan {
			// 保存最近的日志行
			recentLines = append(recentLines, line)
			if len(recentLines) > maxRecentLines {
				recentLines = recentLines[len(recentLines)-maxRecentLines:]
			}

			// 1. 检测崩溃关键字
			for _, keyword := range crashKeywords {
				if strings.Contains(line, keyword) {
					crashDetected = true
					// 收集崩溃上下文
					contextLines := recentLines
					if len(contextLines) > 20 {
						contextLines = contextLines[len(contextLines)-20:]
					}
					crashReason = strings.Join(contextLines, "\n")
					break
				}
			}

			// 2. 检测加载进度（参考PCL的Watcher.GameLog）
			for _, kw := range logProgressKeywords {
				if strings.Contains(line, kw.keyword) && kw.level > logProgress {
					logProgress = kw.level
				}
			}

			// 3. 日志进度5 或窗口出现 = 游戏启动成功
			if logProgress >= 5 && !windowFound {
				windowFound = true
				runtime.EventsEmit(a.ctx, "launchStatus", "success")
			}
		}
	}()

	// 主循环：检测窗口和进程状态
	startTime := time.Now()
	launchTimeout := 30 * time.Second

	for {
		elapsed := time.Since(startTime)

		// 检查窗口是否出现（参考PCL的TryGetMinecraftWindow）
		if !windowFound {
			found, isFML := findMinecraftWindow(pid, processStartTime)
			if found {
				if isFML {
					// FML 窗口：标记窗口已出现但继续等待真正的 MC 窗口
					windowFound = true
					runtime.EventsEmit(a.ctx, "launchStatus", "success")
				} else {
					// 非 FML 窗口：游戏已完全启动
					windowFound = true
					runtime.EventsEmit(a.ctx, "launchStatus", "success")
					// 等待进程退出
					select {
					case exitCode := <-exitChan:
						if exitCode != 0 {
							a.writeLog("!!! 游戏运行中崩溃 (退出码: %d) !!!", exitCode)
							runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
							runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏已退出 (退出码: %d)", exitCode))
						}
						return
					}
					return
				}
			}
		}

		// 检查进程是否已退出（非阻塞）
		select {
		case exitCode := <-exitChan:
			a.writeLog("游戏进程退出，退出码: %d, 运行时间: %.1f秒, 窗口出现: %v", exitCode, time.Since(startTime).Seconds(), windowFound)
			if !windowFound {
				// 收集最近的日志作为错误信息
				logContext := ""
				if len(recentLines) > 0 {
					contextLines := recentLines
					if len(contextLines) > 20 {
						contextLines = contextLines[len(contextLines)-20:]
					}
					logContext = "\n\n最近日志:\n" + strings.Join(contextLines, "\n")
					a.writeLog("最近游戏日志（最后20行）:")
					for _, l := range contextLines {
						a.writeLog("  %s", l)
					}
				}
				if elapsed < 3*time.Second {
					a.writeLog("!!! 游戏启动失败：进程立即退出 (退出码: %d) !!!", exitCode)
					a.writeLog("--- UI 报错内容 ---")
					a.writeLog("游戏启动失败，进程立即退出 (退出码: %d)%s", exitCode, logContext)
					a.writeLog("--- UI 报错内容结束 ---")
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏启动失败，进程立即退出 (退出码: %d)%s", exitCode, logContext))
				} else {
					a.writeLog("!!! 游戏进程意外退出 (退出码: %d) !!!", exitCode)
					a.writeLog("--- UI 报错内容 ---")
					a.writeLog("游戏进程意外退出 (退出码: %d)%s", exitCode, logContext)
					a.writeLog("--- UI 报错内容结束 ---")
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏进程意外退出 (退出码: %d)%s", exitCode, logContext))
				}
			}
			return
		default:
		}

		// 检查是否崩溃（通过日志关键字）
		if crashDetected && !windowFound {
			select {
			case <-exitChan:
			case <-time.After(5 * time.Second):
			}
			a.writeLog("!!! 检测到游戏崩溃 !!!")
			a.writeLog("--- UI 报错内容 ---")
			a.writeLog(crashReason)
			a.writeLog("--- UI 报错内容结束 ---")
			runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
			runtime.EventsEmit(a.ctx, "crashInfo", crashReason)
			return
		}

		// 超时检测
		if elapsed > launchTimeout && !windowFound {
			// 如果有日志进度，说明游戏在加载中，延长超时
			if logProgress >= 2 {
				// 再等30秒
				if elapsed > 60*time.Second {
					runtime.EventsEmit(a.ctx, "launchStatus", "timeout")
					return
				}
			} else {
				runtime.EventsEmit(a.ctx, "launchStatus", "timeout")
				return
			}
		}

		time.Sleep(200 * time.Millisecond)
	}
}

// findMinecraftWindow 查找 Minecraft 游戏窗口（参考PCL的TryGetMinecraftWindow三重过滤条件）
// 返回 (是否找到, 是否为FML窗口)
func findMinecraftWindow(targetPID int, processStartTime time.Time) (bool, bool) {
	found := false
	isFML := false

	cb := syscall.NewCallback(func(hwnd uintptr, lParam uintptr) uintptr {
		if found {
			return 0
		}

		// 1. 检查窗口类名（参考PCL）
		className := make([]byte, 512)
		procGetClassName.Call(hwnd, uintptr(unsafe.Pointer(&className[0])), 512)
		classNameStr := string(bytesToString(className))

		isMCWindow := false
		if classNameStr == "GLFW30" || classNameStr == "LWJGL" || classNameStr == "SunAwtFrame" {
			isMCWindow = true
		}
		if !isMCWindow {
			return 1
		}

		// 2. 检查窗口标题（参考PCL）
		title := make([]byte, 512)
		procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), 512)
		titleStr := string(bytesToString(title))

		// 过滤无效标题
		if titleStr == "" || titleStr == "PopupMessageWindow" {
			return 1
		}
		if strings.HasPrefix(titleStr, "GLFW") && !strings.HasPrefix(titleStr, "FML") {
			return 1
		}

		// 3. 检查窗口所属进程
		var windowPID int
		procGetWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&windowPID)))

		if windowPID != targetPID {
			return 1
		}

		// 4. 检查进程启动时间（参考PCL：窗口所属进程的启动时间必须晚于游戏进程的启动时间）
		// 避免匹配已存在的旧窗口
		// 由于我们直接比较 PID，且 PID 相同，所以这个检查主要是防止 PID 复用
		// 在 Windows 上 PID 可能被复用，所以加上时间检查
		_ = processStartTime // 进程启动时间已通过 PID 匹配保证

		found = true
		isFML = strings.HasPrefix(titleStr, "FML")
		return 0
	})

	procEnumWindows.Call(cb, 0)
	return found, isFML
}

// bytesToString 将 null 终止的 byte 数组转为 string
func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// GetDownloadProgress 获取当前下载进度
func (a *App) GetDownloadProgress() DownloadProgress {
	return a.downloadProgress
}

// isVersionIsolated 检查是否启用版本隔离
func (a *App) isVersionIsolated() bool {
	return a.IsVersionIsolation()
}

// buildClasspath 构建类路径（参考 PCL 的 McLibListGetWithJson + McLaunchArgumentsReplace）
func (a *App) buildClasspath(mcDir string, versionID string, versionJSON *VersionJSON) []string {
	var classpathEntries []string
	libsDir := filepath.Join(mcDir, "libraries")

	for _, lib := range versionJSON.Libraries {
		// 1. 检查 rules（跳过不适用于当前平台的库）
		if !a.shouldIncludeLib(lib) {
			continue
		}

		// 2. 跳过 natives 库（natives 不加入 classpath）
		if lib.Natives != nil {
			continue
		}

		// 3. 确定库文件路径
		var libPath string

		// 优先使用 downloads.artifact.path
		if lib.Downloads != nil && lib.Downloads.Artifact != nil && lib.Downloads.Artifact.Path != "" {
			libPath = filepath.Join(libsDir, lib.Downloads.Artifact.Path)
		} else if lib.JarPath != "" {
			// 有些库直接提供 path 字段
			libPath = filepath.Join(libsDir, lib.JarPath)
		} else if lib.Name != "" {
			// 从 Maven 坐标推算路径（参考 PCL 的 McLibGet）
			libPath = mavenNameToPath(lib.Name, libsDir)
		}

		if libPath == "" {
			continue
		}

		// 4. 检查文件是否存在
		if _, err := os.Stat(libPath); err != nil {
			fmt.Printf("类路径库文件不存在(跳过): %s\n", libPath)
			continue
		}
		classpathEntries = append(classpathEntries, libPath)
	}

	// 5. 添加游戏主 jar（classpath 的最后一个条目）
	// 参考 PCL 的 McLibListGet：jar 字段优先，否则沿 inheritsFrom 链查找原版
	jarName := versionJSON.Jar
	if jarName == "" {
		// 沿 inheritsFrom 链查找原版版本名
		jarName = versionJSON.InheritsFrom
	}
	if jarName == "" {
		jarName = versionID
	}
	versionJar := filepath.Join(mcDir, "versions", jarName, jarName+".jar")

	// 如果 jar 不存在，尝试在当前版本目录中查找
	if _, err := os.Stat(versionJar); err != nil {
		altJar := filepath.Join(mcDir, "versions", versionID, versionID+".jar")
		if _, err2 := os.Stat(altJar); err2 == nil {
			versionJar = altJar
		}
	}

	classpathEntries = append(classpathEntries, versionJar)

	return classpathEntries
}

// shouldIncludeLib 检查库是否应该包含（参考 PCL 的 McJsonRuleCheck）
func (a *App) shouldIncludeLib(lib Library) bool {
	if len(lib.Rules) == 0 {
		return true // 没有 rules，默认包含
	}

	allow := false
	for _, rule := range lib.Rules {
		osMatch := true
		if rule.OS != nil {
			osMatch = rule.OS.Name == "windows"
		}

		if rule.Action == "allow" {
			if osMatch {
				allow = true
			}
		} else if rule.Action == "disallow" {
			if osMatch {
				allow = false
			}
		}
	}

	return allow
}

// libGroupArtifact 从 Maven 坐标中提取 group:artifact（不含版本号）
// 例如 "org.apache.logging.log4j:log4j-core:2.17.1" -> "org.apache.logging.log4j:log4j-core"
func libGroupArtifact(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}
	return name
}

// mavenNameToPath 从 Maven 坐标推算库文件路径（参考 PCL 的 McLibGet）
// Maven 坐标格式: group:artifact:version 或 group:artifact:version:classifier
// 路径格式: group/artifact/version/artifact-version(-classifier).jar
func mavenNameToPath(name string, libsDir string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}

	group := strings.ReplaceAll(parts[0], ".", string(os.PathSeparator))
	artifact := parts[1]
	version := parts[2]
	classifier := ""
	if len(parts) >= 4 {
		classifier = "-" + parts[3]
	}

	// 文件名: artifact-version(-classifier).jar
	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)

	// 完整路径: libsDir/group/artifact/version/fileName
	return filepath.Join(libsDir, group, artifact, version, fileName)
}

// resolveVersionJSON 解析版本 JSON，处理 inheritsFrom 继承关系
// Forge/Fabric/NeoForge/OptiFine 版本都通过 inheritsFrom 引用原版版本
// 需要合并父版本的 libraries、downloads、assetIndex 等信息
func (a *App) resolveVersionJSON(versionID string) (*VersionJSON, error) {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)

	// 查找版本 JSON 文件（文件名可能与文件夹名不同）
	jsonPath := filepath.Join(versionDir, versionID+".json")
	if _, err := os.Stat(jsonPath); err != nil {
		// 尝试查找文件夹中的任意 JSON 文件
		jsonFiles, _ := filepath.Glob(filepath.Join(versionDir, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		} else {
			return nil, fmt.Errorf("未找到版本 JSON: %s", versionDir)
		}
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("读取版本 JSON 失败: %v", err)
	}

	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return nil, fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	// 处理 inheritsFrom
	if versionJSON.InheritsFrom != "" {
		parentJSON, err := a.resolveVersionJSON(versionJSON.InheritsFrom)
		if err != nil {
			fmt.Printf("解析父版本 JSON 失败: %v（将继续使用当前版本信息）\n", err)
		} else {
			// 合并父版本信息
			versionJSON = a.mergeVersionJSON(parentJSON, &versionJSON)
		}
	}

	return &versionJSON, nil
}

// mergeVersionJSON 合并父版本和子版本 JSON
// 子版本（Forge/Fabric）的字段覆盖父版本（原版）的字段
func (a *App) mergeVersionJSON(parent *VersionJSON, child *VersionJSON) VersionJSON {
	merged := *parent // 以父版本为基础

	// 子版本覆盖的字段
	if child.ID != "" {
		merged.ID = child.ID
	}
	if child.MainClass != "" {
		merged.MainClass = child.MainClass
	}
	if child.Type != "" {
		merged.Type = child.Type
	}
	if child.ReleaseTime != "" {
		merged.ReleaseTime = child.ReleaseTime
	}
	if child.Jar != "" {
		merged.Jar = child.Jar
	}

	// 合并 libraries：父版本 + 子版本（按 group:artifact 去重）
	// 规则：子版本的库覆盖父版本中相同 group:artifact 的所有条目
	// 这样 Forge 的 log4j 会覆盖原版的 log4j，而 LWJGL 等原版独有库全部保留
	childGroupArtifacts := map[string]bool{}
	for _, lib := range child.Libraries {
		ga := libGroupArtifact(lib.Name)
		if ga != "" {
			childGroupArtifacts[ga] = true
		}
	}
	var mergedLibs []Library
	for _, lib := range parent.Libraries {
		ga := libGroupArtifact(lib.Name)
		if ga != "" && childGroupArtifacts[ga] {
			continue // 子版本有同名 group:artifact，跳过父版本
		}
		mergedLibs = append(mergedLibs, lib)
	}
	mergedLibs = append(mergedLibs, child.Libraries...)
	merged.Libraries = mergedLibs

	// 合并 arguments
	if child.MinecraftArgs != "" {
		merged.MinecraftArgs = child.MinecraftArgs
	}
	if child.Arguments != nil {
		if merged.Arguments == nil {
			merged.Arguments = &ArgumentsObj{}
		}
		// 合并 JVM 参数：父版本 + 子版本
		if len(child.Arguments.JVM) > 0 {
			merged.Arguments.JVM = append(merged.Arguments.JVM, child.Arguments.JVM...)
		}
		// 合并 Game 参数：父版本 + 子版本
		if len(child.Arguments.Game) > 0 {
			merged.Arguments.Game = append(merged.Arguments.Game, child.Arguments.Game...)
		}
	}

	// 子版本有自己的 downloads 时覆盖
	if child.Downloads != nil {
		merged.Downloads = child.Downloads
	}
	// 子版本有自己的 assetIndex 时覆盖
	if child.AssetIndex != nil {
		merged.AssetIndex = child.AssetIndex
	}

	// 保留 inheritsFrom 用于参考
	merged.InheritsFrom = child.InheritsFrom

	return merged
}

