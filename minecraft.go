package main

import (
	"archive/zip"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unsafe"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ===== Win32 API 用于窗口检测 =====

var (
	user32DLL           = syscall.NewLazyDLL("user32.dll")
	kernel32DLL         = syscall.NewLazyDLL("kernel32.dll")
	procEnumWindows     = user32DLL.NewProc("EnumWindows")
	procGetClassName    = user32DLL.NewProc("GetClassNameA")
	procGetWindowText   = user32DLL.NewProc("GetWindowTextA")
	procGetWindowPID    = user32DLL.NewProc("GetWindowThreadProcessId")
	procOpenProcess     = kernel32DLL.NewProc("OpenProcess")
	procGetProcessTimes = kernel32DLL.NewProc("GetProcessTimes")
	procCloseHandle     = kernel32DLL.NewProc("CloseHandle")
)

// 下载体积上限，防止恶意服务器用无限流把磁盘/内存写爆。
const (
	maxJavaInstallerBytes   = 500 << 20 // 500 MiB，JRE 安装包实际 ~40-70 MiB
	maxAuthlibPrefetchBytes = 1 << 20   // 1 MiB，authlibinjector 抓取的皮肤站首页
	maxVersionManifestBytes = 8 << 20   // 8 MiB，版本清单/资产索引 JSON
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
type DownloadItem struct {
	ID            string  `json:"id"`
	URL           string  `json:"url"`
	CustomName    string  `json:"customName"`
	Type          string  `json:"type"`
	ItemType      string  `json:"itemType"`
	JavaMajor     int     `json:"javaMajor"`
	SavePath      string  `json:"savePath"`
	LoaderName    string  `json:"loaderName"`
	LoaderVersion string  `json:"loaderVersion"`
	OptiFineType  string  `json:"optifineType"`
	OptiFinePatch string  `json:"optifinePatch"`
	Status        string  `json:"status"`
	Progress      float64 `json:"progress"`
	ErrorMsg      string  `json:"errorMsg"`
	// SizeBytes 是该任务“声明”的下载字节数（来自可信镜像/Modrinth files[].size）。
	// 0 表示未知（服务端未给大小），不参与聚合字节预算求和；负数永远不应出现，
	// 预算内核会拒绝。该字段仅用于下载队列的聚合磁盘预算，不改变分发逻辑。
	SizeBytes int64 `json:"sizeBytes"`
}

// 版本 JSON 相关结构体

type VersionJSON struct {
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	MainClass     string            `json:"mainClass"`
	MinecraftArgs string            `json:"minecraftArguments"`
	Arguments     *ArgumentsObj     `json:"arguments"`
	Libraries     []Library         `json:"libraries"`
	Downloads     *VersionDownloads `json:"downloads"`
	AssetIndex    *AssetIndexRef    `json:"assetIndex"`
	ReleaseTime   string            `json:"releaseTime"`
	InheritsFrom  string            `json:"inheritsFrom"`
	Jar           string            `json:"jar"`
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
	URL       string            `json:"url"`
	JarPath   string            `json:"path"`
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
	Action   string          `json:"action"`
	OS       *RuleOS         `json:"os"`
	Features map[string]bool `json:"features"`
}

type RuleOS struct {
	Name    string `json:"name"`
	Arch    string `json:"arch"`
	Version string `json:"version"`
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

// InstalledVersionInfo 安装版本的信息
type InstalledVersionInfo struct {
	FolderName string `json:"folderName"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Loader     string `json:"loader"`
	Type       string `json:"type"`
}

func (a *App) getMinecraftDir() string { return a.GetMinecraftDir() }

func (a *App) emitProgress(status string, currentFile string, downloaded, total int64) {
	var pct float64
	if total > 0 {
		pct = float64(downloaded) / float64(total) * 100
	}
	a.downloadProgress = DownloadProgress{
		TotalBytes: total, DownloadedBytes: downloaded, Percentage: pct,
		CurrentFile: currentFile, Status: status,
	}
	a.downloadMutex.Lock()
	for i := range a.downloadList {
		if a.downloadList[i].Status == "downloading" {
			a.downloadList[i].Progress = pct
			break
		}
	}
	a.downloadMutex.Unlock()
	runtime.EventsEmit(a.ctx, "downloadProgress", a.downloadProgress)
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
}

func (a *App) AddToDownloadList(versionID string, versionURL string, customName string, versionType string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	// 版本名会直接成为 versions/<name>/<name>.json 的目录段，走严格名单段内核：
	// 控制字符、路径分隔符、Windows 保留设备名、尾点空格、超长一律拒绝（而不是像旧
	// sanitizeVersionName 那样静默删字符，导致用户以为写入的目录与实际不一致）。
	safeName, why := SafeVersionComponent(customName)
	if why != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
			"minecraft", "拒绝非法版本下载名: "+describeNameReject(why))
		return fmt.Errorf("版本名称无效: %s", describeNameReject(why))
	}
	customName = safeName
	pending := DownloadItem{
		ID: versionID, URL: versionURL, CustomName: customName,
		Type: versionType, ItemType: "game", Status: "pending", Progress: 0,
	}
	if why := auditDownloadItemForEnqueue(a.downloadList, pending); why != dqRejectNone {
		return fmt.Errorf("%s", describeQueueReject(why))
	}
	if why := auditDownloadItemFields(pending, a.GetMinecraftDir()); why != dfRejectNone {
		return fmt.Errorf("%s", describeDownloadFieldReject(why))
	}
	a.downloadList = append(a.downloadList, pending)
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

func (a *App) AddToDownloadListWithLoader(versionID string, versionURL string, customName string, versionType string, loaderName string, loaderVersion string, optifineType string, optifinePatch string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	safeName, why := SafeVersionComponent(customName)
	if why != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
			"minecraft", "拒绝非法版本下载名: "+describeNameReject(why))
		return fmt.Errorf("版本名称无效: %s", describeNameReject(why))
	}
	customName = safeName
	// loaderName / loaderVersion 会被拼进展示名，最终也成为版本目录名，同样必须是
	// 干净单段（前端可传任意字符串，不能假设它只来自官方加载器版本列表）。
	if loaderName != "" {
		safeLoader, whyL := SafeLoaderComponent(loaderName)
		if whyL != nameRejectNone {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
				"minecraft", "拒绝非法加载器名: "+describeNameReject(whyL))
			return fmt.Errorf("加载器名称无效: %s", describeNameReject(whyL))
		}
		safeLoaderVer, whyV := SafeLoaderComponent(loaderVersion)
		if whyV != nameRejectNone {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
				"minecraft", "拒绝非法加载器版本: "+describeNameReject(whyV))
			return fmt.Errorf("加载器版本无效: %s", describeNameReject(whyV))
		}
		loaderName, loaderVersion = safeLoader, safeLoaderVer
	}
	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在同名版本: %s", customName)
		}
	}
	displayName := customName
	if loaderName != "" {
		displayName += " (" + loaderName + " " + loaderVersion + ")"
	}
	// 拼接后的完整名也要过长度/单段校验（customName 合法但加上 loader 后缀可能超长）。
	if finalName, whyD := SafeVersionDisplayName(displayName); whyD != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
			"minecraft", "拒绝非法版本展示名: "+describeNameReject(whyD))
		return fmt.Errorf("版本名称无效: %s", describeNameReject(whyD))
	} else {
		displayName = finalName
	}
	pending := DownloadItem{
		ID: versionID, URL: versionURL, CustomName: displayName, Type: versionType,
		ItemType: "game+loader", LoaderName: loaderName, LoaderVersion: loaderVersion,
		OptiFineType: optifineType, OptiFinePatch: optifinePatch, Status: "pending", Progress: 0,
	}
	if why := auditDownloadItemForEnqueue(a.downloadList, pending); why != dqRejectNone {
		return fmt.Errorf("%s", describeQueueReject(why))
	}
	if why := auditDownloadItemFields(pending, a.GetMinecraftDir()); why != dfRejectNone {
		return fmt.Errorf("%s", describeDownloadFieldReject(why))
	}
	a.downloadList = append(a.downloadList, pending)
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

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
	if majorVer < 0 || majorVer > 99 {
		return fmt.Errorf("Java 主版本号超出合理范围: %d", majorVer)
	}
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	customName := "Java " + fmt.Sprintf("%d", majorVer)
	pending := DownloadItem{
		ID: fmt.Sprintf("java-%d", majorVer), URL: target.URL, CustomName: customName,
		Type: "java", ItemType: "java", JavaMajor: majorVer, Status: "pending", Progress: 0,
	}
	if why := auditDownloadItemForEnqueue(a.downloadList, pending); why != dqRejectNone {
		return fmt.Errorf("%s", describeQueueReject(why))
	}
	if why := auditDownloadItemFields(pending, a.GetMinecraftDir()); why != dfRejectNone {
		return fmt.Errorf("%s", describeDownloadFieldReject(why))
	}
	a.downloadList = append(a.downloadList, pending)
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

func (a *App) RemoveFromDownloadList(customName string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	for i, item := range a.downloadList {
		if item.CustomName == customName {
			a.downloadList = append(a.downloadList[:i], a.downloadList[i+1:]...)
			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
			return nil
		}
	}
	return fmt.Errorf("未找到: %s", customName)
}

func (a *App) GetDownloadList() []DownloadItem {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	result := make([]DownloadItem, len(a.downloadList))
	copy(result, a.downloadList)
	return result
}

func (a *App) GetDownloadListCount() int {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	return len(a.downloadList)
}

func (a *App) StartDownloadList() error {
	a.downloadMutex.Lock()
	if a.isDownloading {
		a.downloadMutex.Unlock()
		return fmt.Errorf("正在下载中，请等待当前下载完成")
	}
	if len(a.downloadList) == 0 {
		a.downloadMutex.Unlock()
		return fmt.Errorf("下载列表为空")
	}
	// r35：开始下载前做“分目录磁盘余量预检”。按各 pending 条目的 SavePath 聚合已知
	// 声明大小，逐卷探测剩余空间，任何目录写入会击穿 1GiB 安全水位就整体拒绝开始，
	// 避免把盘写到耗尽。未知大小 / 探测失败一律不拦（没有证据不能误杀）。
	demands := groupDownloadDiskDemand(a.downloadList)
	plans := planDownloadDiskFit(demands, probeDownloadDiskFit)
	if blocked := blockingDiskPlans(plans); len(blocked) > 0 {
		for _, bp := range blocked {
			recordSecurityEvent("download", auditSeverityCritical, auditActionBlocked,
				"disk-space", describeDiskPlanBlock(bp))
		}
		a.downloadMutex.Unlock()
		return fmt.Errorf("%s", describeDiskPlanBlock(blocked[0]))
	}
	a.isDownloading = true
	a.downloadCancel = make(chan struct{})
	a.downloadMutex.Unlock()
	go func() {
		defer func() {
			a.downloadMutex.Lock()
			a.isDownloading = false
			a.downloadCancel = nil
			a.downloadMutex.Unlock()
			runtime.EventsEmit(a.ctx, "downloadListCompleted")
		}()
		for {
			select {
			case <-a.downloadCancel:
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
			if item.ItemType == "java" {
				err = a.downloadJavaItem(item.JavaMajor, item.URL)
			} else if item.ItemType == "mod" {
				err = a.downloadModItem(item)
			} else if item.ItemType == "loader" {
				err = a.downloadLoaderItem(item)
			} else if item.ItemType == "modpack" {
				err = a.installModpack(item)
			} else if item.ItemType == "game+loader" {
				a.emitProgress("downloading", "下载原版游戏 "+item.ID, 0, 0)
				if err = a.DownloadVersion(item.ID, item.URL, item.ID); err != nil {
					err = fmt.Errorf("下载原版游戏失败: %v", err)
				} else {
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
				a.downloadList[idx].ErrorMsg = err.Error()
			} else {
				a.downloadList[idx].Status = "completed"
				a.downloadList[idx].Progress = 100
			}
			a.downloadMutex.Unlock()
			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
		}
	}()
	return nil
}

func (a *App) CancelDownloadList() error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	if !a.isDownloading || a.downloadCancel == nil {
		return fmt.Errorf("当前没有正在进行的下载")
	}
	close(a.downloadCancel)
	return nil
}

func (a *App) downloadJavaItem(majorVer int, url string) error {
	target, why := auditJavaDownloadRequest(majorVer, url, a.GetJavaDownloadList())
	if why != jdRejectNone {
		recordSecurityEvent(auditCategoryInstaller, auditSeverityCritical, auditActionBlocked,
			"minecraft", "Java 下载请求被拒绝: "+describeJavaDownloadReject(why))
		return fmt.Errorf("Java 下载请求被拒绝: %s", describeJavaDownloadReject(why))
	}
	if target.IsWebPage {
		// 交给系统浏览器前先过结构性校验：只允许 https 公网域名，拒绝危险 scheme、
		// userinfo 混淆、内网/本机/裸 IP 与控制字符，避免 rundll32 打开到 file:/SSRF。
		cmd, openErr := BrowserOpenCommand(url)
		if openErr != nil {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
				"minecraft", "拒绝打开不安全的 Java 下载页: "+openErr.Error())
			return fmt.Errorf("Java 下载页链接不安全: %w", openErr)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Run()
	}
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}
	if strings.ContainsAny(target.FileName, `/\\`) || strings.HasPrefix(target.FileName, `..`) {
		return fmt.Errorf(`不安全的 Java 安装文件名: %s`, target.FileName)
	}
	destPath := filepath.Join(tempDir, target.FileName)
	// %TEMP% 对同用户其它进程可写：不能看到同名文件就直接执行，否则恶意程序
	// 预先放一个同名 msi/exe 就会被我们拉起。先清掉残留（符号链接只删链接
	// 本身），本次下载的内容才是即将被校验执行的内容。发现残留本身值得审计：
	// 正常首次下载时这里应该什么都没有。
	if pre, statErr := os.Lstat(destPath); statErr == nil {
		kind := "普通文件"
		if pre.Mode()&os.ModeSymlink != 0 {
			kind = "符号链接"
		} else if !pre.Mode().IsRegular() {
			kind = "特殊文件"
		}
		recordSecurityEvent(auditCategoryInstaller, auditSeverityCritical, auditActionBlocked,
			"minecraft", "TEMP 中发现预置同名安装包("+kind+")，拒绝执行并清除: "+destPath)
	}
	if err := removeStaleInstaller(destPath); err != nil {
		return fmt.Errorf("清理旧安装包失败: %v", err)
	}
	a.emitProgress("downloading", target.FileName, 0, 0)
	ctx, cancelReq := a.downloadContext()
	defer cancelReq()
	// 安装包与普通游戏文件走同一条安全通道：HTTPS 强制、声明/实际体积双校验、
	// 临时文件流式落盘 + fsync + 原子 rename、503/网络抖动指数退避重试，
	// 失败不会在 TEMP 留半截安装包。安装包紧接着要被执行，落盘后必须补
	// Mark of the Web（ZoneId=3 Internet），让 SmartScreen 按互联网来源处置，
	// 而不是把刚下载的文件当成本机原生文件。
	opts := secureDownloadOptions{
		MaxBytes:      maxJavaInstallerBytes,
		Attempts:      3,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Client:        safeHTTPClient(),
		MarkWebOrigin: true,
		Progress: func(received, total int64) {
			a.emitProgress("downloading", target.FileName, received, total)
		},
	}
	if _, err := streamVerifiedDownload(ctx, target.URL, destPath, opts); err != nil {
		if errors.Is(err, errSecureDownloadTooLarge) {
			return fmt.Errorf("下载失败 %s: %w", target.URL, errDownloadTooLarge)
		}
		return fmt.Errorf("下载失败: %v", err)
	}
	return runInstaller(destPath, target.IsMSI)
}

func runInstaller(filePath string, isMSI bool) error {
	if err := validateInstallerPackage(filePath, isMSI); err != nil {
		recordSecurityEvent(auditCategoryInstaller, auditSeverityCritical, auditActionBlocked,
			"minecraft", "安装包执行前校验失败: "+err.Error())
		return err
	}
	if isMSI {
		cmd := exec.Command("msiexec", "/i", filePath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Start()
	}
	cmd := exec.Command("explorer", filePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

func (a *App) DownloadVersion(versionID string, versionURL string, customName string) error {
	mcDir := a.getMinecraftDir()
	// customName 既可能来自前端，也可能来自 .mrpack 清单里的 dependencies.minecraft
	// （installModpack 原样透传到这里），属于外部输入，必须走严格名单段内核，防止
	// 形如 "../../evil" / "CON" / "a\x00b" 的值把版本文件写到 versions 目录之外。
	safeName, why := SafeVersionComponent(customName)
	if why != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"minecraft", "拒绝非法版本目录名: "+describeNameReject(why))
		return fmt.Errorf("无效的版本名称: %s", describeNameReject(why))
	}
	customName = safeName
	versionDir := filepath.Join(mcDir, "versions", customName)
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}
	a.emitProgress("downloading", customName+".json", 0, 0)
	jsonURL := rewriteLauncherURLToBMCL(versionURL)
	jsonPath := filepath.Join(versionDir, customName+".json")
	if err := a.downloadFileBounded(jsonURL, jsonPath, false, maxMetadataJSONBytes); err != nil {
		return fmt.Errorf("下载版本 JSON 失败: %v", err)
	}
	jsonData, err := readBoundedFile(jsonPath, maxMetadataJSONBytes)
	if err != nil {
		return fmt.Errorf("读取版本 JSON 失败: %v", err)
	}
	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	// 先把清单内 URL 归一化为真正发起请求时的地址（BMCLAPI 重写是确定性、受信任的），
	// 白名单审计必须针对“实际抓取主机”，否则会误杀走 launcher.mojang.com 的老清单，
	// 也避免攻击者靠“审计看 A、实际请求 B”的差异绕过。
	if versionJSON.Downloads != nil {
		if versionJSON.Downloads.Client != nil {
			versionJSON.Downloads.Client.URL = rewriteLauncherURLToBMCL(versionJSON.Downloads.Client.URL)
		}
		if versionJSON.Downloads.Server != nil {
			versionJSON.Downloads.Server.URL = rewriteLauncherURLToBMCL(versionJSON.Downloads.Server.URL)
		}
	}
	for i := range versionJSON.Libraries {
		dl := versionJSON.Libraries[i].Downloads
		if dl == nil {
			continue
		}
		if dl.Artifact != nil {
			dl.Artifact.URL = rewriteLauncherURLToBMCL(dl.Artifact.URL)
		}
		for _, art := range dl.Classifiers {
			if art != nil {
				art.URL = rewriteLauncherURLToBMCL(art.URL)
			}
		}
	}
	if versionJSON.AssetIndex != nil {
		versionJSON.AssetIndex.URL = rewriteLauncherURLToBMCL(versionJSON.AssetIndex.URL)
	}
	// 版本 JSON 来自可由前端指定的第三方 versionURL，client / library / native 的
	// url/path/sha1 全部不受信任：下载主机必须落在官方 / 镜像白名单，可执行产物必须
	// 带合法 SHA1，库路径必须是严格 Maven 相对路径，资源索引 ID 必须是单段安全名。
	// critical 一律拒绝下载（防止攻击者把 jar 指向自己的服务器落进 classpath）。
	manifestFindings := auditVersionManifest(&versionJSON)
	for i := range manifestFindings {
		f := &manifestFindings[i]
		if f.Severity == manifestCritical {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityCritical, auditActionBlocked,
				"version-manifest", f.Field+": "+f.Detail)
		} else {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionDetected,
				"version-manifest", f.Field+": "+f.Detail)
		}
	}
	if manifestHasCritical(manifestFindings) {
		return manifestCriticalError(manifestFindings)
	}
	if versionJSON.Downloads != nil && versionJSON.Downloads.Client != nil {
		client := versionJSON.Downloads.Client
		clientURL := rewriteLauncherURLToBMCL(client.URL)
		jarPath := filepath.Join(versionDir, customName+".jar")
		a.emitProgress("downloading", customName+".jar", 0, client.Size)
		if err := a.downloadVerifiedFile(clientURL, jarPath, client.SHA1, true); err != nil {
			return fmt.Errorf("下载客户端 jar 失败: %v", err)
		}
	}
	a.emitProgress("downloading", "库文件", 0, 0)
	for _, lib := range versionJSON.Libraries {
		if lib.Downloads == nil {
			continue
		}
		if lib.Downloads.Artifact != nil {
			artifact := lib.Downloads.Artifact
			// Zip Slip 防护：库路径走严格 Maven 相对路径白名单（拒盘符/反斜杠/冒号）
			safePath := SafeMavenRelPath(artifact.Path)
			if safePath == "" {
				fmt.Printf("跳过不安全的库路径: %s\n", artifact.Path)
				continue
			}
			libPath := filepath.Join(mcDir, "libraries", filepath.FromSlash(safePath))
			libURL := rewriteLauncherURLToBMCL(artifact.URL)
			a.emitProgress("downloading", filepath.Base(artifact.Path), 0, artifact.Size)
			if err := a.downloadVerifiedFile(libURL, libPath, artifact.SHA1, false); err != nil {
				fmt.Printf("下载库文件失败(跳过): %s, %v\n", artifact.Path, err)
			}
		}
		if lib.Natives != nil {
			// 仍只选择 Windows 系列分类器，但按真实架构挑选 windows-x86 /
			// windows-64 / windows-arm64，并正确替换 ${arch}（旧实现恒为 "64"，
			// 在 32 位 / ARM64 上会取错本地库）。
			winEnv := ruleEnv{osName: "windows", osArch: currentRuleEnv().osArch}
			nativeKey, ok := resolveWindowsNativeKey(lib.Natives, winEnv)
			if !ok {
				continue
			}
			if lib.Downloads.Classifiers == nil {
				continue
			}
			classifier, ok := lib.Downloads.Classifiers[nativeKey]
			if !ok || classifier == nil {
				continue
			}
			// Zip Slip 防护：native 路径走严格 Maven 相对路径白名单
			safeClassPath := SafeMavenRelPath(classifier.Path)
			if safeClassPath == "" {
				fmt.Printf("跳过不安全的 native 路径: %s\n", classifier.Path)
				continue
			}
			nativePath := filepath.Join(mcDir, "libraries", filepath.FromSlash(safeClassPath))
			nativeURL := rewriteLauncherURLToBMCL(classifier.URL)
			a.emitProgress("downloading", filepath.Base(classifier.Path), 0, classifier.Size)
			if err := a.downloadVerifiedFile(nativeURL, nativePath, classifier.SHA1, false); err != nil {
				fmt.Printf("下载 native 失败: %s, %v\n", classifier.Path, err)
			}
		}
	}
	if versionJSON.AssetIndex != nil {
		assetIndexRef := versionJSON.AssetIndex
		// 资产索引 ID 来自外部版本 JSON，会直接拼进文件路径，必须强制为
		// 单段安全名，防止 "1.21/../../x.json" 之类路径穿越或落到非预期位置。
		safeIndexID := SafeSimpleName(assetIndexRef.ID)
		if safeIndexID == "" {
			return fmt.Errorf("资产索引 ID 不安全，拒绝继续: %q", assetIndexRef.ID)
		}
		assetIndexDir := filepath.Join(mcDir, "assets", "indexes")
		assetIndexPath := filepath.Join(assetIndexDir, safeIndexID+".json")
		assetIndexURL := rewriteLauncherURLToBMCL(assetIndexRef.URL)
		a.emitProgress("downloading", "资源索引", 0, 0)
		if err := a.downloadFileBounded(assetIndexURL, assetIndexPath, false, maxMetadataJSONBytes); err != nil {
			fmt.Printf("下载资源索引失败: %v\n", err)
		} else {
			assetIndexData, err := readBoundedFile(assetIndexPath, maxMetadataJSONBytes)
			if err == nil {
				var assetIndex AssetIndex
				if json.Unmarshal(assetIndexData, &assetIndex) == nil {
					totalAssets := len(assetIndex.Objects)
					count := 0
					for name, obj := range assetIndex.Objects {
						count++
						// 对象哈希既拼下载 URL 也拼本地 objects/xx/<40hex> 路径，
						// 且会做 hash[:2] 切片：必须严格是 40 位小写十六进制，
						// 否则既可能路径穿越，也会因长度不足直接 panic 崩溃。
						if !IsLowerHex(obj.Hash, 40) {
							a.writeLog("跳过哈希非法的资源 %s: %q", name, obj.Hash)
							continue
						}
						// 对象 key 会原样拼进下载 URL，拒绝穿越段 / 反斜杠 / 控制字符。
						safeName, whyName := validateAssetObjectName(name)
						if whyName != aoOK {
							a.writeLog("跳过资源名非法的对象 %q: %s", name, describeAssetReject(whyName))
							continue
						}
						hash := obj.Hash
						subHash := hash[:2]
						assetURL := rewriteLauncherURLToBMCL(fmt.Sprintf("https://launcher.mojang.com/v1/objects/%s/%s", hash, safeName))
						assetPath := filepath.Join(mcDir, "assets", "objects", subHash, hash)
						a.emitProgress("downloading", fmt.Sprintf("资源 %d/%d", count, totalAssets), int64(count), int64(totalAssets))
						if _, err := os.Stat(assetPath); os.IsNotExist(err) {
							if derr := a.downloadFile(assetURL, assetPath, false); derr != nil {
								fmt.Printf("下载资源失败(跳过): %s, %v\n", name, derr)
							}
						}
					}
				}
			}
		}
	}
	a.emitProgress("extracting", "natives", 0, 0)
	nativesDir := filepath.Join(versionDir, customName+"-natives")
	if err := os.MkdirAll(nativesDir, 0700); err != nil {
		return fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, &versionJSON)
	nativesEntries, err := os.ReadDir(nativesDir)
	if err == nil && len(nativesEntries) == 0 {
		a.writeLog("警告: natives 目录为空，游戏可能无法启动")
	}
	a.emitProgress("completed", "", 100, 100)
	return nil
}

// checkFileHash 校验文件完整性（SHA1，用于验证 Mojang manifest 提供的哈希）
func (a *App) checkFileHash(filePath string, expectedSHA1 string) bool {
	info, err := os.Stat(filePath)
	if err != nil || info.Size() == 0 {
		return false
	}
	if expectedSHA1 == "" {
		return true
	}
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	actualHash := fmt.Sprintf("%x", h.Sum(nil))
	return actualHash == expectedSHA1
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
	for attempt, url := range urls {
		os.Remove(destPath)
		if err := a.downloadFileBounded(url, destPath, false, maxBytes); err != nil {
			a.writeLog("下载失败 [%s]: %v", url, err)
			// 切下一个镜像前做一次可中断的退避（mt_xor25 抖动 ±25%），
			// 既避免失败后瞬间重试压垮镜像，也让多实例不会同步重试；取消下载立即返回。
			if attempt+1 < len(urls) {
				base := time.Duration(attempt+1) * 500 * time.Millisecond
				if !a.sleepOrCancel(mtXor25Jitter(base)) {
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

func (a *App) fixAssetsIndex(mcDir string, versionJSON *VersionJSON) {
	if versionJSON.AssetIndex == nil || versionJSON.AssetIndex.URL == "" {
		return
	}
	// AssetIndex.ID 来自不可信版本 JSON，会拼成 indexes/<id>.json 落盘路径，
	// 必须和 DownloadVersion 主路径一样过单段安全名校验，拒绝 "../" 等穿越名。
	safeID := SafeSimpleName(versionJSON.AssetIndex.ID)
	if safeID == "" {
		a.writeLog("资源索引 ID 不安全，拒绝补全: %q", versionJSON.AssetIndex.ID)
		recordSecurityEvent("asset", "high", "reject-asset-index-id", "fixAssetsIndex", versionJSON.AssetIndex.ID)
		return
	}
	assetIndexDir := filepath.Join(mcDir, "assets", "indexes")
	assetIndexPath := filepath.Join(assetIndexDir, safeID+".json")
	if _, err := os.Stat(assetIndexPath); err == nil {
		return
	}
	a.writeLog("资源索引文件缺失，正在下载: %s", safeID)
	// 目标目录由 downloadFromMirrors→downloadFileBounded 统一以 0700 创建/收权，无需预建。
	urls := a.getMirrorURLs(versionJSON.AssetIndex.URL)
	for i, u := range urls {
		urls[i] = rewriteMetaIndexURLToBMCL(u)
	}
	if a.downloadFromMirrors(urls, assetIndexPath, maxMetadataJSONBytes) {
		a.writeLog("资源索引文件下载完成: %s", safeID)
		a.fixMissingAssets(mcDir, assetIndexPath)
	} else {
		a.writeLog("资源索引文件下载失败: %s", safeID)
	}
}

func (a *App) fixMissingAssets(mcDir string, assetIndexPath string) {
	data, err := readBoundedFile(assetIndexPath, maxMetadataJSONBytes)
	if err != nil {
		return
	}
	var index AssetIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return
	}
	// 统一走 assetguard：哈希严格 40 位小写 hex、对象名相对路径校验、条数与大小收口。
	// 历史上这里只判 hash != "" 就 obj.Hash[:2]，短哈希会越界 panic，畸形哈希还能让
	// Join 出的落盘路径逃出 objects 目录（远程 DoS / 路径穿越写）。
	safeObjects, rejects, why := auditAssetObjects(index.Objects)
	if why == aoIndexTooMany {
		a.writeLog("资产索引对象条数超过上限 %d，拒绝补全", maxAssetIndexObjects)
		recordSecurityEvent("asset", "high", "reject-asset-index-too-many", "fixMissingAssets",
			fmt.Sprintf("objects=%d limit=%d", len(index.Objects), maxAssetIndexObjects))
		return
	}
	if n := rejects[aoHashBad]; n > 0 {
		recordSecurityEvent("asset", "high", "reject-bad-asset-hash", "fixMissingAssets",
			fmt.Sprintf("count=%d", n))
	}
	objectsDir := filepath.Join(mcDir, "assets", "objects")
	missingCount, downloadedCount := 0, 0
	total := len(safeObjects)
	for i, obj := range safeObjects {
		sub, objPath, ok := planAssetObjectDest(objectsDir, obj.Hash)
		if !ok {
			continue
		}
		if _, err := os.Stat(objPath); err == nil {
			continue
		}
		missingCount++
		originalURL := fmt.Sprintf("https://resources.download.minecraft.net/%s/%s", sub, obj.Hash)
		urls := a.getMirrorURLs(originalURL)
		a.emitProgress("downloading", fmt.Sprintf("补全资源 %d/%d", i+1, total), int64(i+1), int64(total))
		// objPath 的父目录由 downloadFromMirrors 内部统一按 0700 创建/收权。
		if a.downloadFromMirrors(urls, objPath, maxAssetObjectBytes) {
			downloadedCount++
		}
	}
	if len(rejects) > 0 {
		rejectedTotal := 0
		for _, n := range rejects {
			rejectedTotal += n
		}
		a.writeLog("资产索引存在 %d 个非法对象，已跳过", rejectedTotal)
	}
	if missingCount > 0 {
		a.writeLog("资源文件补全: 缺失 %d 个, 成功下载 %d 个", missingCount, downloadedCount)
	}
}

// 单个 / 全部 native 条目解压后的体积上限。
// 正常的 .dll / .so / .jnilib 远小于这些值，上限只在“异常压缩包 / zip 炸弹”时触发，
// 避免一个恶意 natives jar 借超大条目或高压缩比把磁盘写满。
const (
	maxNativeEntryBytes int64 = 256 << 20 // 256 MiB / 单个 native
	maxNativeTotalBytes int64 = 2 << 30   // 2 GiB / 单次解压总量
)

func extractNatives(jarPath string, destDir string) (int, error) {
	return extractNativesWithLimits(jarPath, destDir, maxNativeEntryBytes, maxNativeTotalBytes)
}

// extractNativesWithLimits 是真正的解压内核，单文件 / 总量上限由调用方传入，
// 既让生产路径用固定安全常量，也便于用小阈值对体积边界做轻量单测（不必造几百 MiB 数据）。
func extractNativesWithLimits(jarPath string, destDir string, entryMax, totalMax int64) (int, error) {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		os.Remove(jarPath)
		return 0, fmt.Errorf("打开 Natives 文件失败（文件可能已损坏）: %s", jarPath)
	}
	defer r.Close()
	count := 0
	var total int64
	for _, f := range r.File {
		if f.FileInfo().IsDir() || strings.HasPrefix(f.Name, "META-INF/") {
			continue
		}
		// 符号链接 / 设备等特殊条目绝不落地，即便伪装成 .dll 后缀。
		if f.Mode()&(os.ModeSymlink|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 {
			continue
		}
		lowerName := strings.ToLower(f.Name)
		if !strings.HasSuffix(lowerName, ".dll") && !strings.HasSuffix(lowerName, ".jnilib") && !strings.HasSuffix(lowerName, ".so") {
			continue
		}
		// zip 头里声明的解压体积可先廉价挡一刀；真正的边界仍靠 LimitReader，不信任该值。
		if f.UncompressedSize64 > uint64(entryMax) {
			return count, fmt.Errorf("native 条目 %s 声明体积超过单文件上限", f.Name)
		}
		if total >= totalMax || total+int64(f.UncompressedSize64) > totalMax {
			return count, fmt.Errorf("native 解压总量超过 %d 字节上限，疑似 zip 炸弹", totalMax)
		}
		fileName := filepath.Base(f.Name)
		destPath := filepath.Join(destDir, fileName)
		if info, err := os.Stat(destPath); err == nil && info.Size() == f.FileInfo().Size() {
			count++
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		if err := os.MkdirAll(destDir, 0700); err != nil {
			rc.Close()
			return count, fmt.Errorf("创建 natives 目录失败: %v", err)
		}
		// 先写到同目录临时文件，完整通过体积校验后再原子替换，避免留下半截大文件。
		tmp, err := os.CreateTemp(destDir, ".native-*.tmp")
		if err != nil {
			rc.Close()
			continue
		}
		tmpName := tmp.Name()
		limited := io.LimitReader(rc, entryMax+1)
		n, copyErr := io.Copy(tmp, limited)
		tmp.Close()
		rc.Close()
		if copyErr != nil {
			os.Remove(tmpName)
			continue
		}
		if n > entryMax || total+n > totalMax {
			os.Remove(tmpName)
			if n > entryMax {
				return count, fmt.Errorf("native 条目 %s 解压后超过单文件上限", fileName)
			}
			return count, fmt.Errorf("native 解压总量超过 %d 字节上限，疑似 zip 炸弹", totalMax)
		}
		if err := os.Chmod(tmpName, 0600); err != nil {
			os.Remove(tmpName)
			continue
		}
		if err := os.Rename(tmpName, destPath); err != nil {
			os.Remove(tmpName)
			continue
		}
		total += n
		count++
	}
	return count, nil
}

func (a *App) extractNativesFromJSON(mcDir string, nativesDir string, versionJSON *VersionJSON) {
	// 解压根目录统一收权到 0700（历史上若存在 0755 的 natives 目录会被原样沿用）。
	_ = ensurePrivateDir(nativesDir)
	for _, lib := range versionJSON.Libraries {
		if lib.Natives == nil {
			continue
		}
		// 与下载阶段使用同一套“按真实架构选 Windows natives 键 + ${arch} 替换”
		// 的规则，避免下载和解压挑到不同分类器（旧实现这里只看 windows-64/windows）。
		winEnv := ruleEnv{osName: "windows", osArch: currentRuleEnv().osArch}
		nativeKey, hasNative := resolveWindowsNativeKey(lib.Natives, winEnv)
		if !hasNative {
			continue
		}
		if lib.Downloads == nil || lib.Downloads.Classifiers == nil {
			continue
		}
		classifier, ok := lib.Downloads.Classifiers[nativeKey]
		if !ok || classifier == nil {
			continue
		}
		// 与下载阶段一致，这里必须再次校验 classifier.Path：版本 JSON 来自镜像
		// 站（不可信），而本函数也会被非 DownloadVersion 的其它启动流程调用。
		safeClassifierPath := isSafeRelPath(classifier.Path)
		if safeClassifierPath == "" {
			a.writeLog("跳过不安全的 native jar 路径: %s", classifier.Path)
			continue
		}
		nativeJarPath := filepath.Join(mcDir, "libraries", safeClassifierPath)
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
}

func isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true, err
	}
	return len(entries) == 0, nil
}

func (a *App) setGameLanguage(gameDir string, versionID string) {
	optionsPath := filepath.Join(gameDir, "options.txt")
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
	requiredLang := "zh_cn"
	if mcCodeMain > 0 && mcCodeMain < 12 {
		requiredLang = "zh_CN"
	}
	if _, err := os.Stat(optionsPath); os.IsNotExist(err) {
		yosbrPath := filepath.Join(gameDir, "config", "yosbr", "options.txt")
		if _, err2 := os.Stat(yosbrPath); err2 == nil {
			optionsPath = yosbrPath
			a.writeLog("检测到 Yosbr Mod，修改其 options.txt")
		}
	}
	data, err := readBoundedFile(optionsPath, localTextConfigMaxBytes)
	if err != nil {
		if errors.Is(err, errLocalFileTooLarge) {
			// 异常巨大的 options.txt：绝不能走下面“创建默认文件”的分支把它截断覆盖，
			// 直接跳过本次语言设置，保留用户原文件。
			a.writeLog("options.txt 异常过大，跳过语言设置以免破坏文件: %v", err)
			recordSecurityEvent("local-config", auditSeverityWarn, auditActionBlocked,
				"minecraft", "options.txt 超过有界读取上限，已跳过语言改写")
			return
		}
		content := fmt.Sprintf("lang:%s\n", requiredLang)
		if err := secureWritePrivateFile(optionsPath, []byte(content)); err != nil {
			a.writeLog("创建 options.txt 失败: %v", err)
		} else {
			a.writeLog("已创建 options.txt，设置语言为 %s", requiredLang)
		}
		return
	}
	lines := strings.Split(string(data), "\n")
	found, hasSaves := false, false
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
		lines = append(lines, fmt.Sprintf("lang:%s", requiredLang))
	}
	newData := strings.Join(lines, "\n")
	if err := secureWritePrivateFile(optionsPath, []byte(newData)); err != nil {
		a.writeLog("写入 options.txt 失败: %v", err)
	} else {
		a.writeLog("已将游戏语言设置为 %s", requiredLang)
	}
}

func (a *App) ensureNativesForLoader(mcDir string, versionID string, versionDir string, nativesDir string, versionJSON *VersionJSON) {
	if rawParent := strings.TrimSpace(versionJSON.InheritsFrom); rawParent != "" {
		parentName := safeVersionName(rawParent)
		if parentName != "" {
			parentNativesDir := filepath.Join(mcDir, "versions", parentName, parentName+"-natives")
			if entries, err := os.ReadDir(parentNativesDir); err == nil && len(entries) > 0 {
				fmt.Printf("从父版本复制 natives: %s -> %s\n", parentNativesDir, nativesDir)
				copyDirContents(parentNativesDir, nativesDir)
				return
			}
		}
	}
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
	fmt.Printf("尝试重新解压 natives 到: %s\n", nativesDir)
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
}

// copyDirContents 只复制 srcDir 顶层的普通文件到 dstDir（不递归）。
// 显式跳过符号链接 / 特殊文件，并对单文件与总量设上限：源目录是各版本 natives，
// 正常只含体积有限的 .dll/.so；跳过链接可避免把链接目标（可能指向目录外敏感文件）
// 以普通文件形式带进运行目录。
//
// 复制统一走 copyFileSecure 的“流式 + 原子写 + 源/目标符号链接拒绝 + 多读 1
// 判超限”，不再用 os.ReadFile 把单个最多 256MiB 的文件整体读进内存（那会造成
// 与文件等大的瞬时内存峰值）；这里只按声明大小记账，实际超限由 copyFileSecure
// 在流式阶段兜底。
const maxCopyDirEntryBytes int64 = 256 << 20

func copyDirContents(srcDir string, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// ReadDir 不跟随链接：任何非常规文件（符号链接 / 设备 / 管道等）一律跳过。
		if entry.Type()&os.ModeType != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		size := info.Size()
		if size > maxCopyDirEntryBytes || total+size > maxNativeTotalBytes {
			continue
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())
		// copyFileSecure 内部会再做一次源链接检查、目标链接拒绝，并以 LimitReader
		// 多读 1 字节发现“声明大小正常但读取中持续增长”的文件。
		if err := copyFileSecure(srcPath, dstPath, 0600, maxCopyDirEntryBytes); err != nil {
			continue
		}
		total += size
	}
	return nil
}

// generateOfflineUUID 使用 UMFS 哈希（bool-hybrid-array 生态）
func generateOfflineUUID(username string) string {
	data := "OfflinePlayer:" + username
	hash := NewUMFS([]byte(data)).Digest()
	hash[6] = (hash[6] & 0x0f) | 0x30
	hash[8] = (hash[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
}

var crashKeywords = []string{
	"Crash report saved to", "This crash report has been saved to:",
	"Could not save crash report to", "Someone is closing me!",
	"Restarting Minecraft with command", "An exception was thrown, the game will display an error screen and halt.",
	"UNABLE TO LAUNCH", "Failed to start the Minecraft runtime",
	"Exception in thread", "java.lang.UnsatisfiedLinkError",
	"java.lang.NoClassDefFoundError", "java.lang.OutOfMemoryError",
	"Unable to launch", "java.lang.reflect.InvocationTargetException",
}

var logProgressKeywords = []struct {
	level   int
	keyword string
}{
	{2, "Setting user:"}, {3, "LWJGL Version:"}, {3, "lwjgl version"},
	{4, "OpenAL initialized"}, {4, "Starting up SoundSystem"},
	{5, "Created: "}, {5, "textures"}, {5, "-atlas"},
}

func shouldIncludeArg(arg map[string]interface{}) bool {
	// 条件化参数统一走 ruleengine：裸 map 的 rules 被翻译成通用规则后按 Mojang
	// 语义评估（os.name/arch/version + features），与库过滤共用同一内核，避免
	// 两份实现漂移。旧实现只认 windows、且 features 只要出现 is_demo_user 键
	// （无论真假值）就拒绝，会把 {"is_demo_user":false} 的正常参数误删。
	return argumentObjectAllowed(arg, currentRuleEnv())
}

func deduplicateJvmArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	type argGroup struct {
		fullKey string
		parts   []string
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
			current.fullKey = current.fullKey + "\x00" + arg
			current.parts = append(current.parts, arg)
		}
	}
	if current.fullKey != "" {
		groups = append(groups, current)
	}
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

func findMinecraftWindow(targetPID int, processStartTime time.Time) (bool, bool) {
	found, isFML := false, false
	cb := syscall.NewCallback(func(hwnd uintptr, lParam uintptr) uintptr {
		if found {
			return 0
		}
		className := make([]byte, 512)
		procGetClassName.Call(hwnd, uintptr(unsafe.Pointer(&className[0])), 512)
		classNameStr := string(bytesToString(className))
		isMCWindow := classNameStr == "GLFW30" || classNameStr == "LWJGL" || classNameStr == "SunAwtFrame"
		if !isMCWindow {
			return 1
		}
		title := make([]byte, 512)
		procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), 512)
		titleStr := string(bytesToString(title))
		if titleStr == "" || titleStr == "PopupMessageWindow" {
			return 1
		}
		if strings.HasPrefix(titleStr, "GLFW") && !strings.HasPrefix(titleStr, "FML") {
			return 1
		}
		var windowPID int
		procGetWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&windowPID)))
		if windowPID != targetPID {
			return 1
		}
		found = true
		isFML = strings.HasPrefix(titleStr, "FML")
		return 0
	})
	procEnumWindows.Call(cb, 0)
	return found, isFML
}

func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func (a *App) GetDownloadProgress() DownloadProgress { return a.downloadProgress }
func (a *App) isVersionIsolated() bool               { return a.IsVersionIsolation() }

// sanitizeLaunchUsername 清洗进入游戏命令行参数的用户名。
// 老版本 version JSON 的 MinecraftArgs 是按空格切分的字符串，
// 用户名里只要含空格/制表符/控制字符，就能在 ${auth_player_name} 处
// 注入任意额外游戏参数（参数注入）。这里剔除空白与控制字符、按 16 个
// rune 截断（Minecraft 用户名上限），清洗后为空则回退 Player。
// 正版用户名本身只会含字母数字下划线，此清洗不影响正常用户。
func sanitizeLaunchUsername(raw string) string {
	var b strings.Builder
	count := 0
	for _, r := range raw {
		if count >= 16 {
			break
		}
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
		count++
	}
	name := b.String()
	if name == "" {
		return "Player"
	}
	return name
}

func (a *App) buildLaunchArgs(versionID string, versionJSON *VersionJSON, mcDir string, versionDir string) ([]string, string, string, string) {
	isOldJSON := versionJSON.MinecraftArgs != ""
	javaEntry, _ := a.SelectJavaForVersion(versionID)
	maxMem, minMem := "2G", "1G"
	if config, _ := a.GetGlobalConfig(); config != nil {
		// r34：-Xmx/-Xms 不再裸拼 config 整数。SaveGlobalConfig 不校验堆配置，旧实现
		// 会把 0 / 负数 / 极大值 / min>max 原样拼成 "-Xmx1000000G" 等非法参数导致 JVM
		// 启动失败。统一在拼接点走 heapsizeguard 归一（GB 口径、1TiB 上界、min<=max），
		// 任何收敛都记录一次安全审计，便于排查被改脏的配置。
		safeMin, safeMax, heapCodes := ResolveHeapSizesGB(config.MinMemory, config.MaxMemory)
		if len(heapCodes) > 0 {
			recordSecurityEvent(auditCategoryLaunch, auditSeverityWarn, auditActionStripped,
				"minecraft", "游戏堆内存配置已归一: "+strings.Join(heapCodes, ","))
		}
		maxMem = FormatHeapSizeGB(safeMax)
		minMem = FormatHeapSizeGB(safeMin)
	}
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	classpathEntries := a.buildClasspath(mcDir, versionID, versionJSON)

	// 最终归属验收（必须在 resolveJVMArg 使用 classpath 拼出 -cp 之前完成）：不相信
	// buildClasspath 内各拼路径环节，对整条 classpath 统一收敛——必须全部是 .minecraft
	// 内的绝对 .jar、无 UNC/穿越/控制符，并去重。越界条目剔除并留痕，用安全去重后的
	// 条目重建 classpath；后续 Forge 过滤只会再收窄（仍是安全子集）。
	cpAudit := AuditGameClasspath(classpathEntries, []string{mcDir})
	for _, f := range cpAudit.Findings {
		if f.Severity == launchSeverityCritical {
			recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
				"minecraft", "游戏 classpath 不安全条目已剔除: "+f.Code)
		}
	}
	if len(cpAudit.SafeEntries) != len(classpathEntries) {
		classpathEntries = cpAudit.SafeEntries
	}
	classpath := strings.Join(classpathEntries, ";")
	if lpAudit := AuditGameLocalPaths(nativesDir, filepath.Join(mcDir, "libraries"),
		filepath.Join(mcDir, "assets"), []string{mcDir}); lpAudit.HasCritical() {
		recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
			"minecraft", "游戏本地路径(natives/libraries/assets)审计未通过: "+lpAudit.FirstCriticalCode())
	}
	gameDir := versionDir
	if !a.IsVersionIsolation() {
		gameDir = mcDir
	}

	var jvmArgs []string
	if isOldJSON {
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem), fmt.Sprintf("-Xms%s", minMem),
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			"-XX:+UnlockExperimentalVMOptions", "-XX:+UseG1GC",
			"-XX:G1NewSizePercent=20", "-XX:G1ReservePercent=20",
			"-XX:MaxGCPauseMillis=50", "-XX:G1HeapRegionSize=32M",
		}
	} else {
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem), fmt.Sprintf("-Xms%s", minMem),
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			fmt.Sprintf("-Dorg.lwjgl.librarypath=%s", nativesDir),
		}
		if versionJSON.Arguments != nil {
			var untrusted []string
			for _, arg := range versionJSON.Arguments.JVM {
				untrusted = append(untrusted, resolveJVMArg(arg, nativesDir, mcDir, classpath, versionID)...)
			}
			// arguments.jvm 来自 Mojang/加载器下发的版本 JSON，本质上是外部数据。
			// 被篡改或恶意的整合包版本 JSON 可在此塞入 -javaagent / -XX:OnError
			// 等参数，在 JVM 启动阶段直接执行任意代码（见 filterUntrustedJvmArgs）。
			safeJvmArgs, blockedJvmArgs, jvmArgTruncated := filterUntrustedJvmArgs(untrusted)
			jvmArgs = append(jvmArgs, safeJvmArgs...)
			for _, bad := range blockedJvmArgs {
				a.writeLog("已拦截版本 JSON 中的危险 JVM 参数: %s", bad)
			}
			if jvmArgTruncated {
				a.writeLog("版本 JSON 的 JVM 参数数量超过 %d，多余参数已丢弃", maxUntrustedJvmArgs)
			}
		}
	}

	isForgeNew := (strings.Contains(versionID, "forge") || strings.Contains(versionJSON.MainClass, "bootstraplauncher")) && javaEntry.MajorVer >= 17
	if isForgeNew {
		var filtered []string
		for _, entry := range classpathEntries {
			if strings.Contains(entry, "versions") && strings.HasSuffix(entry, ".jar") {
				base := strings.ToLower(strings.TrimSuffix(filepath.Base(entry), ".jar"))
				if !strings.Contains(base, "forge") && !strings.Contains(base, "fabric") &&
					!strings.Contains(base, "neoforge") && !strings.Contains(base, "quilt") {
					continue
				}
			}
			filtered = append(filtered, entry)
		}
		classpathEntries = filtered
		classpath = strings.Join(classpathEntries, ";")
	}

	isFabric := strings.Contains(versionID, "fabric") || strings.Contains(versionJSON.MainClass, "fabricmc") || strings.Contains(versionJSON.MainClass, "knot")
	if isFabric && len(classpathEntries) > 0 {
		var paths []string
		for _, p := range classpathEntries {
			paths = append(paths, "file:///"+strings.ReplaceAll(p, "\\", "/"))
		}
		jvmArgs = append(jvmArgs, "-Dfabric.classPathGroups=default:"+strings.Join(paths, ";"))
	}
	jvmArgs = deduplicateJvmArgs(jvmArgs)
	// 安全缓解属性必须由启动器拍板：剔除来自启动器/版本 JSON/加载器的任何同名 -D
	// （防止不可信 JSON 用后置 =false 覆盖 formatMsgNoLookups），并在 JVM 参数段
	// 末尾统一下发 log4j 消息 lookup 关闭与 JNDI 远程 codebase 禁用。
	jvmArgs = applyEnforcedJvmProperties(jvmArgs)

	username := "Player"
	currentUser, err := a.GetCurrentUser()
	if err == nil && currentUser.Username != "" {
		username = sanitizeLaunchUsername(currentUser.Username)
	}
	uuid := generateOfflineUUID(username)
	accessToken := uuid
	userType := "msa"

	if currentUser.Type == UserTypePremium {
		authData, authErr := a.GetMSAuthData(username)
		if authErr == nil && authData.MCAccessToken != "" {
			_ = a.RefreshMicrosoftToken(username)
			authData, authErr = a.GetMSAuthData(username)
			if authErr == nil {
				uuid = authData.UUID
				accessToken = authData.MCAccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s", uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
			}
		}
	}
	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(username)
		if extErr == nil && extData.AccessToken != "" {
			_ = a.RefreshExternalToken(username)
			extData, extErr = a.GetExternalAuthData(username)
			if extErr == nil {
				uuid = extData.UUID
				accessToken = extData.AccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s", uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
			}
		}
	}

	assetIndexName := ""
	if versionJSON.AssetIndex != nil {
		assetIndexName = versionJSON.AssetIndex.ID
	}
	replacements := map[string]string{
		"${auth_player_name}": username, "${version_name}": versionID,
		"${game_directory}": gameDir, "${assets_root}": filepath.Join(mcDir, "assets"),
		"${assets_index_name}": assetIndexName, "${auth_uuid}": uuid,
		"${auth_access_token}": accessToken, "${access_token}": accessToken,
		"${auth_session}": accessToken, "${user_type}": userType,
		"${version_type}": "QGL", "${user_properties}": "{}",
		"${game_assets}": filepath.Join(mcDir, "assets", "virtual", "legacy"),
		"${classpath}":   classpath, "${classpath_separator}": ";",
		"${natives_directory}": nativesDir, "${library_directory}": filepath.Join(mcDir, "libraries"),
		"${launcher_name}": "QGL", "${launcher_version}": "1.0.0",
		"${resolution_width}": "854", "${resolution_height}": "480",
	}

	// 启动器自己生成、随后替换进游戏参数的可信值（账号用户名/UUID/会话令牌/资源索引
	// ID）必须干净：它们一旦含空白、引号或 CR/LF，就会在被字符串替换拼进 argv 时劈开
	// 额外参数（旧版 MinecraftArgs 是纯字符串替换，尤其敏感）。账号数据可能来自损坏的
	// 本地账号文件或异常的第三方认证响应，这里统一做控制字符/超长兜底，命中即放弃启动。
	reservedValues := map[string]string{
		"username":    username,
		"uuid":        uuid,
		"accessToken": accessToken,
		"assetIndex":  assetIndexName,
		"version":     versionID,
		"userType":    userType,
	}
	rvAudit := AuditReservedGameValues(reservedValues)
	if rvAudit.HasCritical() {
		for _, f := range rvAudit.Findings {
			if f.Severity == launchSeverityCritical {
				recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionRejected,
					"minecraft", "启动器保留参数值异常: "+f.Code+" @ "+f.Field)
			}
		}
		a.writeLog("账号/会话参数含非法控制字符或超长，放弃启动")
		return nil, "", "", ""
	}

	var gameArgs []string
	if isOldJSON {
		for _, part := range strings.Split(versionJSON.MinecraftArgs, " ") {
			arg := part
			for k, v := range replacements {
				arg = strings.ReplaceAll(arg, k, v)
			}
			gameArgs = append(gameArgs, arg)
		}
	}
	if versionJSON.Arguments != nil {
		for _, arg := range versionJSON.Arguments.Game {
			gameArgs = append(gameArgs, resolveGameArg(arg, replacements)...)
		}
	}

	// 游戏参数最终验收：旧版 MinecraftArgs 与 arguments.game 都来自外部版本 JSON。
	// resolveGameArg 已挡住“一个值夹空格劈成多条”，这里再拦“本身合法成条”的会话劫持
	// 参数（--server/--port/--quickPlay*/--proxy*，官方 JSON 绝不会自带）与控制字符/
	// 超长值，并给条数上界。剔除劫持项后可继续；参数表被畸形放大则放弃启动。
	gaAudit := AuditExternalGameArgs(gameArgs)
	for _, f := range gaAudit.Findings {
		if f.Severity == launchSeverityCritical {
			recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionStripped,
				"minecraft", "外部游戏参数审计: "+f.Code+" @ "+f.Field)
		}
	}
	if gameFindingsContainCode(gaAudit.Findings, "ga-too-many") {
		a.writeLog("外部游戏参数条数超过上限，放弃启动")
		return nil, "", "", ""
	}
	gameArgs = gaAudit.SafeExternal

	hasCp := false
	for i, arg := range jvmArgs {
		if arg == "-cp" && i+1 < len(jvmArgs) {
			hasCp = true
		}
	}
	var allArgs []string
	if hasCp {
		allArgs = append(jvmArgs, versionJSON.MainClass)
	} else {
		allArgs = append(jvmArgs, "-cp", classpath, versionJSON.MainClass)
	}
	allArgs = append(allArgs, gameArgs...)
	return allArgs, classpath, username, gameDir
}

// sanitizePathComponent 验证路径组件不含路径遍历字符
func sanitizePathComponent(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("无效的路径组件: %s", name)
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\:*?"<>|`) {
		return fmt.Errorf("无效的路径组件: %s", name)
	}
	return nil
}

// localArtifactMissing 报告目标文件是否不存在或为 0 字节（下载中断/被清理的典型形态）。
func localArtifactMissing(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return info.IsDir() || info.Size() == 0
}

// fixMissingLibraries 在启动前补齐版本清单要求、但本地缺失（或为空）的库与 Windows
// 本地库。它只复用版本安装阶段那条已审计的安全下载链：主机白名单在
// downloadVerifiedFile 内强制、相对路径走 SafeMavenRelPath 防 Zip Slip、SHA1 用清单
// 官方锚校验；本函数绝不新增任何旁路。已存在且非空的文件不重下（侧车复核仍在
// downloadVerifiedFile / verifyCachedFile 一侧，这里只为“缺失”场景补下载）。
func (a *App) fixMissingLibraries(mcDir string, versionJSON *VersionJSON) {
	if versionJSON == nil {
		return
	}
	winEnv := ruleEnv{osName: "windows", osArch: currentRuleEnv().osArch}
	libsDir := filepath.Join(mcDir, "libraries")

	fetchArtifact := func(art *LibArtifact, label string) {
		if art == nil {
			return
		}
		safeRel := SafeMavenRelPath(art.Path)
		if safeRel == "" {
			a.writeLog("补全库时跳过不安全路径: %s", art.Path)
			return
		}
		dest := filepath.Join(libsDir, filepath.FromSlash(safeRel))
		if !localArtifactMissing(dest) {
			return
		}
		a.emitProgress("downloading", filepath.Base(safeRel), 0, art.Size)
		if err := a.downloadVerifiedFile(rewriteLauncherURLToBMCL(art.URL), dest, art.SHA1, false); err != nil {
			a.writeLog("补全库文件失败(跳过): %s, %v", label, err)
		}
	}

	for i := range versionJSON.Libraries {
		lib := &versionJSON.Libraries[i]
		if !a.shouldIncludeLib(*lib) || lib.Downloads == nil {
			continue
		}
		fetchArtifact(lib.Downloads.Artifact, lib.Name)
		if lib.Natives != nil && lib.Downloads.Classifiers != nil {
			if nativeKey, ok := resolveWindowsNativeKey(lib.Natives, winEnv); ok {
				fetchArtifact(lib.Downloads.Classifiers[nativeKey], lib.Name+":"+nativeKey)
			}
		}
	}
}

func (a *App) LaunchGame(versionID string) error {
	if err := sanitizePathComponent(versionID); err != nil {
		return fmt.Errorf("无效的版本ID: %v", err)
	}
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	a.launchLogPath = filepath.Join(versionDir, "QGL", "Logs", "qgl_launch.log")
	a.writeLog("===== 启动游戏: %s =====", versionID)
	a.writeLog("版本目录: %s", versionDir)

	// 拉起 JVM 前对 mods 目录做存量安全扫描（通用恶意形态 + Log4Shell/JNDI），
	// 覆盖手动拖入 / 其它启动器写入、从未经本程序校验的 jar；命中高危直接拒绝启动。
	if err := a.enforceInstalledModsBeforeLaunch(versionID); err != nil {
		return err
	}

	// mods 完整性审计闸门：基线存在时对账目录，发现被篡改的 mod 默认拦截启动，
	// 除非用户显式开启强制放行（SetModsAuditForceLaunch）。新增 / 缺失仅提示。
	if err := a.enforceModsAuditBeforeLaunch(versionID); err != nil {
		return err
	}

	// 实例并发启动锁：同一版本实例同时只能有一个 JVM 在跑（防止两个进程并发
	// 读写世界存档 / 配置 / 日志互相踩踏）。上锁失败直接拦截；锁在游戏进程
	// 退出后由 watchGameProcess 释放，进程被强杀时靠过期时长兜底接管。
	if _, err := a.acquireInstanceLock(versionID); err != nil {
		return err
	}

	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	runtime.EventsEmit(a.ctx, "launchStatus", "fixing")
	a.emitProgress("downloading", "补全文件中", 0, 0)
	a.fixMissingLibraries(mcDir, versionJSON)

	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	if err := os.MkdirAll(nativesDir, 0700); err != nil {
		return fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
	if empty, _ := isDirEmpty(nativesDir); empty {
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}

	allArgs, _, _, gameDir := a.buildLaunchArgs(versionID, versionJSON, mcDir, versionDir)

	currentUser, _ := a.GetCurrentUser()
	if currentUser.Type == UserTypeExternal {
		username := currentUser.Username
		extData, extErr := a.GetExternalAuthData(username)
		if extErr == nil {
			injectorPath, injErr := a.GetAuthlibInjectorPath()
			if injErr == nil {
				serverURL := extData.ServerURL
				prefetched := ""
				if isHTTPSURL(serverURL) {
					resp, err := safeHTTPClient().Get(serverURL)
					if err == nil {
						// 皮肤站首页本应几 KB；上限 1MiB，防止恶意服务器返回超大响应把
						// JVM 命令行撑爆。走统一有界读内核（多读 1 字节精确判定超限），
						// 读体中断或超量都不预取，而不是像旧实现那样吞掉读错、拿半截内容。
						body, readErr := readBoundedBody(resp.Body, maxAuthlibPrefetchBytes)
						resp.Body.Close()
						if readErr == nil {
							prefetched = base64.StdEncoding.EncodeToString(body)
						}
					}
				}
				injectorArgs := []string{"-javaagent:" + injectorPath + "=" + serverURL, "-Dauthlibinjector.side=client"}
				if prefetched != "" {
					injectorArgs = append(injectorArgs, "-Dauthlibinjector.yggdrasil.prefetched="+prefetched)
				}
				allArgs = append(injectorArgs, allArgs...)
			}
		}
	}

	a.setGameLanguage(gameDir, versionID)

	javaEntry, _ := a.SelectJavaForVersion(versionID)
	javaPath := javaEntry.Path

	// 启动预检：Java 二进制必须是常规文件（Windows 拒绝重解析点/符号链接，防
	// 配置项被换成指向任意程序的链接入口）；游戏目录 / natives 目录必须就绪；
	// 磁盘剩余空间低于安全水位时提示。critical 问题直接拒绝启动。
	preflightIssues, preflightBlocked := aggregatePreflight(
		checkJavaBinary(javaPath),
		checkGameDirs(gameDir, nativesDir),
		checkDiskHeadroom(gameDir, preflightMinFreeBytes),
		checkSymlinkTraps(gameDir),
	)
	for _, it := range preflightIssues {
		recordSecurityEvent("launch-preflight", auditSeverityWarn, auditActionDetected,
			"minecraft", "预检["+it.Code+"] "+it.Text)
	}
	if preflightBlocked {
		recordSecurityEvent("launch-preflight", auditSeverityCritical, auditActionBlocked,
			"minecraft", "启动预检未通过，拒绝启动")
		return fmt.Errorf("启动预检未通过，拒绝启动")
	}

	// 关键配置防篡改基线：Java 路径 / 游戏目录 / 版本选择等启动执行目标字段若在
	// 两次本进程会话之间被外部改动（木马把 javaPath 换成自己投放的 exe），
	// 静态预检看不出来——这里按基线 diff 拒绝启动，防配置投毒。
	if cfg, cfgErr := a.GetGlobalConfig(); cfgErr == nil {
		ucfg, ucfgErr := a.GetUserConfig(currentUser.Username)
		if ucfgErr != nil {
			ucfg = &UserConfig{}
		}
		if baselineErr := a.CheckConfigGuardBaseline(a.configSnapshotOf(cfg, ucfg)); baselineErr != nil {
			return baselineErr
		}
	}

	// 启动参数快照：把“用什么启动”落一份脱敏快照（Java 路径 / 版本 / 内存 /
	// auth 类型 / mods 数量 / 预检结果），与 session journal 互补——日后审计只
	// 看结果不看配置的问题由本模块补上。快照不含任何 token，只记类型。
	authTypeLabel := "offline"
	switch currentUser.Type {
	case UserTypePremium:
		authTypeLabel = "microsoft"
	case UserTypeExternal:
		authTypeLabel = "external"
	}
	// 堆内存与启动参数同源（heapsizeguard 归一后的 safeMax），快照记录 MB 口径。
	maxMemMB := 2048
	if config, cfgErr := a.GetGlobalConfig(); cfgErr == nil && config != nil {
		_, safeMaxGB, _ := ResolveHeapSizesGB(config.MinMemory, config.MaxMemory)
		maxMemMB = safeMaxGB * 1024
	}
	modsCount := 0
	if modsDir, errDir := filepath.Abs(filepath.Join(mcDir, "mods")); errDir == nil {
		if entries, errLs := os.ReadDir(modsDir); errLs == nil {
			modsCount = len(entries)
		}
	}
	a.recordLaunchSnapshot(buildLaunchSnapshot(
		versionID, javaPath, javaEntry.Version, authTypeLabel,
		maxMemMB, modsCount, currentUser.Type == UserTypePremium, preflightBlocked, len(preflightIssues),
	))

	cmdParts := []string{syscall.EscapeArg(javaPath)}
	for _, arg := range allArgs {
		cmdParts = append(cmdParts, syscall.EscapeArg(arg))
	}
	fullCmdLine := strings.Join(cmdParts, " ")
	a.writeLog("命令行长度: %d 字符", len(fullCmdLine))

	// 最终防线：真正被 CreateProcess 解释的是上面拼好的整条字符串（SysProcAttr.CmdLine），
	// 其中混入了版本 JSON、账号、外部认证服务器 URL 等多源数据。在启动前按系统分词规则
	// 还原 argv 并审计：拒绝 CR/LF/NUL 注入、引号不配平、超长串/参数，以及 argv[0] 必须
	// 仍是安全的 java 可执行。critical 一律不启动游戏。
	if _, cmdAudit := AuditCommandLine(fullCmdLine, true); cmdAudit.HasCritical() {
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityCritical, auditActionBlocked,
			"minecraft", "游戏启动命令行最终审计未通过: "+cmdAudit.FirstCriticalCode())
		return fmt.Errorf("游戏启动命令行安全审计未通过，拒绝启动: %s", cmdAudit.FirstCriticalCode())
	}

	cmd := exec.Command(javaPath)
	cmd.Dir = gameDir
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: fullCmdLine}

	// 子进程默认会继承启动器的全部环境变量，而 JAVA_TOOL_OPTIONS /
	// _JAVA_OPTIONS / JDK_JAVA_OPTIONS 等会被 JVM 在启动时自动当作额外参数
	// 加载，绕过我们对版本 JSON 与 JVM 参数的危险参数过滤（可注入任意
	// javaagent / 本地代理）。这里显式下发净化后的环境，只剥掉这一族变量。
	gameEnv, strippedEnv := currentGameEnvironment(nil)
	cmd.Env = gameEnv
	for _, name := range strippedEnv {
		a.writeLog("安全: 已从游戏进程环境中剥离隐式 JVM 参数变量: %s", name)
	}
	// DLL 搜索顺序劫持防护：PATH 只保留系统目录 + Java 目录，剔除用户可写
	// 目录（Downloads / Temp / 网盘同步目录等），防止同名恶意 DLL 被加载进
	// 游戏进程。被剔除条目落审计日志（最多列 10 条，完整计数保留）。
	gameEnv, droppedPath, droppedPathList := sanitizeGameEnv(gameEnv, filepath.Dir(javaPath))
	if droppedPath > 0 {
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityWarn, auditActionDetected,
			"minecraft", fmt.Sprintf("已从游戏进程 PATH 剔除 %d 个非系统目录（防 DLL 劫持），例: %s",
				droppedPath, strings.Join(droppedPathList, "; ")))
	}
	cmd.Env = gameEnv
	if len(strippedEnv) > 0 {
		// 只记录变量名（值可能含敏感路径/令牌），作为"环境被人动过"的留痕。
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityWarn, auditActionStripped,
			"minecraft", "启动游戏时剥离隐式 JVM 参数环境变量: "+strings.Join(strippedEnv, ","))
	}

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
	a.recordSessionStart(versionID, pid)

	go a.watchGameProcess(cmd, stdoutPipe, stderrPipe, pid, processStartTime, versionID)
	return nil
}

func (a *App) GetLaunchCommand(versionID string) (string, error) {
	if err := sanitizePathComponent(versionID); err != nil {
		return "", fmt.Errorf("无效的版本ID: %v", err)
	}
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return "", fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	a.fixMissingLibraries(mcDir, versionJSON)
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	// natives 目录由 extractNativesFromJSON 内部统一以 0700 创建/收权。
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
	if empty, _ := isDirEmpty(nativesDir); empty {
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}
	allArgs, _, _, _ := a.buildLaunchArgs(versionID, versionJSON, mcDir, versionDir)
	javaEntry, _ := a.SelectJavaForVersion(versionID)
	javaPath := javaEntry.Path

	cmdParts := []string{syscall.EscapeArg(javaPath)}
	for _, arg := range allArgs {
		cmdParts = append(cmdParts, syscall.EscapeArg(arg))
	}
	return strings.Join(cmdParts, " "), nil
}

// dumpCrashContext 在判定崩溃后读取“本局”（startTime 之后）新生成的
// crash-reports / hs_err 崩溃产物摘要，追加到崩溃原因；找不到或读取失败都静默
// 退化为原原因，绝不阻塞崩溃上报。gameDir 即游戏进程的工作目录（cmd.Dir）。
func (a *App) dumpCrashContext(reason, gameDir string, startTime time.Time) string {
	// 崩溃上下文统一脱敏（用户目录 / QGL 根 / 游戏目录 / JWT / 长十六进制），
	// 防止 hs_err 里的绝对路径与令牌被贴到论坛或经错误通道外发。
	if gameDir == "" {
		return redactCrashText(reason, a.GetQGLDir(), "", a.currentUsername())
	}
	if s, ok := collectLatestCrashDump(gameDir, startTime); ok {
		extra := renderCrashDumpSummary(s)
		combined := extra
		if reason != "" {
			combined = reason + "\n" + extra
		}
		return redactCrashText(combined, a.GetQGLDir(), gameDir, a.currentUsername())
	}
	return redactCrashText(reason, a.GetQGLDir(), gameDir, a.currentUsername())
}

func (a *App) watchGameProcess(cmd *exec.Cmd, stdoutPipe io.Reader, stderrPipe io.Reader, pid int, processStartTime time.Time, versionID string) {
	// 实例锁在本函数退出（游戏进程结束 / 启动失败 / 超时）时统一释放。
	defer a.releaseInstanceLock(versionID, "")
	// 会话台账结算：无论从哪条路径退出（正常/崩溃/超时/立即退出），都记一条
	// 结局。各 return 前先更新本组变量，defer 在函数尾统一写盘。
	sessionOutcome := SessionOutcomeOk
	sessionExitCode := -1
	sessionDetail := ""
	defer func() {
		a.recordSessionEnd(versionID, pid, sessionExitCode, sessionOutcome, sessionDetail)
		// 会话日志：函数退出时统一落盘 + 轮转（与台账结算同一时机，避免漏记尾部）。
		a.EndGameSessionLog()
	}()
	// 会话日志：本局日志脱敏持久化从这里开始。
	if err := a.BeginGameSessionLog(versionID); err != nil {
		a.writeLog("会话日志初始化失败: %v", err)
	}
	runtime.EventsEmit(a.ctx, "launchStatus", "launching")
	crashDetected, windowFound := false, false
	crashReason := ""
	logProgress := 0
	var recentLines []string
	exitChan := make(chan int, 1)
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
	logChan := make(chan string, 200)
	// 有界流式按行读取：替换默认 bufio.Scanner（单行 64KiB 上限会被超长日志行
	// 静默打断，导致崩溃/进度检测失效；盲目放大缓冲又会被无换行巨行 OOM）。
	// 两个管道都 EOF 后关闭 logChan，让消费 goroutine 能随游戏退出而结束。
	var logWG sync.WaitGroup
	logWG.Add(2)
	pipeGameLog := func(r io.Reader) {
		defer logWG.Done()
		_, truncated, _ := streamBoundedLines(r, maxGameLogLineBytes, func(line string) {
			logChan <- line
		})
		if truncated > 0 {
			recordSecurityEvent("game-log", auditSeverityWarn, auditActionStripped,
				"minecraft", fmt.Sprintf("游戏输出有 %d 行超过 %d 字节单行上限，已截断(防内存膨胀)",
					truncated, maxGameLogLineBytes))
		}
	}
	go pipeGameLog(stdoutPipe)
	go pipeGameLog(stderrPipe)
	go func() {
		logWG.Wait()
		close(logChan)
	}()
	go func() {
		for line := range logChan {
			recentLines = append(recentLines, line)
			if len(recentLines) > 50 {
				recentLines = recentLines[len(recentLines)-50:]
			}
			// 会话日志：脱敏后进环形缓冲，会话结束统一落盘。
			a.AppendGameSessionLine(line)
			for _, kw := range crashKeywords {
				if strings.Contains(line, kw) {
					crashDetected = true
					start := len(recentLines) - 20
					if start < 0 {
						start = 0
					}
					crashReason = buildCrashContext(recentLines[start:])
					break
				}
			}
			for _, kw := range logProgressKeywords {
				if strings.Contains(line, kw.keyword) && kw.level > logProgress {
					logProgress = kw.level
				}
			}
			if logProgress >= 5 && !windowFound {
				windowFound = true
				runtime.EventsEmit(a.ctx, "launchStatus", "success")
			}
		}
	}()
	startTime := time.Now()
	launchTimeout := 30 * time.Second
	for {
		elapsed := time.Since(startTime)
		if !windowFound {
			found, _ := findMinecraftWindow(pid, processStartTime)
			if found {
				windowFound = true
				runtime.EventsEmit(a.ctx, "launchStatus", "success")
				select {
				case exitCode := <-exitChan:
					if exitCode != 0 {
						sessionOutcome = SessionOutcomeCrash
						sessionExitCode = exitCode
						runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
						runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏已退出 (退出码: %d)", exitCode))
					} else {
						sessionOutcome = SessionOutcomeOk
						sessionExitCode = 0
					}
				}
				return
			}
		}
		select {
		case exitCode := <-exitChan:
			a.writeLog("游戏进程退出，退出码: %d, 运行时间: %.1f秒", exitCode, elapsed.Seconds())
			if !windowFound {
				logContext := ""
				if len(recentLines) > 0 {
					start := len(recentLines) - 20
					if start < 0 {
						start = 0
					}
					logContext = "\n\n最近日志:\n" + buildCrashContext(recentLines[start:])
				}
				// 控制台没说清真因时，补读本局 crash-reports / hs_err 崩溃产物。
				if dump := a.dumpCrashContext("", cmd.Dir, processStartTime); dump != "" {
					logContext += "\n\n崩溃诊断:\n" + dump
				}
				if elapsed < 3*time.Second {
					sessionOutcome = SessionOutcomeLaunchFail
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", sanitizeLogLine(fmt.Sprintf("游戏启动失败，进程立即退出 (退出码: %d)%s", exitCode, logContext)))
				} else {
					sessionOutcome = SessionOutcomeCrash
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", sanitizeLogLine(fmt.Sprintf("游戏进程意外退出 (退出码: %d)%s", exitCode, logContext)))
				}
				sessionExitCode = exitCode
				sessionDetail = logContext
			} else {
				if exitCode != 0 {
					sessionOutcome = SessionOutcomeCrash
				} else {
					sessionOutcome = SessionOutcomeOk
				}
				sessionExitCode = exitCode
			}
			return
		default:
		}
		if crashDetected && !windowFound {
			select {
			case <-exitChan:
			case <-time.After(5 * time.Second):
			}
			crashReason = a.dumpCrashContext(crashReason, cmd.Dir, processStartTime)
			sessionOutcome = SessionOutcomeCrash
			sessionDetail = crashReason
			runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
			runtime.EventsEmit(a.ctx, "crashInfo", sanitizeLogLine(crashReason))
			return
		}
		if elapsed > launchTimeout && !windowFound {
			if logProgress >= 2 && elapsed < 60*time.Second {
				// 继续等待
			} else {
				sessionOutcome = SessionOutcomeTimeout
				runtime.EventsEmit(a.ctx, "launchStatus", "timeout")
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}
