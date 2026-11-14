package main

import (
	"syscall"

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
