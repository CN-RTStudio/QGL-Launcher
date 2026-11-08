package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

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

// 单个 / 全部 native 条目解压后的体积上限。
// 正常的 .dll / .so / .jnilib 远小于这些值，上限只在“异常压缩包 / zip 炸弹”时触发，
// 避免一个恶意 natives jar 借超大条目或高压缩比把磁盘写满。
const (
	maxNativeEntryBytes int64 = 256 << 20 // 256 MiB / 单个 native
	maxNativeTotalBytes int64 = 2 << 30   // 2 GiB / 单次解压总量
)

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

func (a *App) isVersionIsolated() bool { return a.IsVersionIsolation() }

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
