package main

import "syscall"

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
