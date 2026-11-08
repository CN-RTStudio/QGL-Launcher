package main

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ===== 安全工具函数 =====

// isHTTPSURL 验证 URL 是否为 HTTPS 协议
// 防止 HTTP 中间人攻击，所有下载 URL 必须使用 HTTPS
func isHTTPSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Scheme == "https"
}

// allowedMavenLibHosts 是允许下载游戏依赖库的 Maven 主机白名单。
// install_profile.json / version.json 来自镜像上不受信任的安装器，其中每个库
// 的 url/sha1 都由安装器作者填写：攻击者可以把某个库的 url 指向自己的服务器，
// 该 jar 最终会落进 libraries 并进入 JVM classpath，等同于远程代码执行。
// 光有 https 和“随安装器自带的 sha1”挡不住这一点（主机和 sha1 都是攻击者写的），
// 所以必须把下载主机限定在官方/可信 Maven 源，再尽量用官方 sha1 复核传输完整性。
var allowedMavenLibHosts = map[string]bool{
	"maven.minecraftforge.net": true,
	"maven.neoforged.net":      true,
	"libraries.minecraft.net":  true,
	"piston-data.mojang.com":   true,
	"maven.fabricmc.net":       true,
	"repo1.maven.org":          true, // Maven Central，部分安装器依赖在此
	"bmclapi2.bangbang93.com":  true, // BMCLAPI 镜像（重写后的目标主机）
}

// isAllowedMavenLibURL 判断依赖库下载 URL 是否落在可信 Maven 主机上。
// 强制 https、不允许 userinfo、只允许默认 443、主机必须精确命中白名单
// （用 map 精确匹配而非后缀匹配，避免 evil-maven.minecraftforge.net.evil.com
// 之类的伪造主机绕过）。
func isAllowedMavenLibURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	if u.Scheme != "https" || u.User != nil {
		return false
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".") // 容忍结尾点，但仍须精确命中
	return allowedMavenLibHosts[host]
}

// readLimited 读取响应体，限制最大大小防止内存耗尽攻击
// 用于 API JSON 响应，最大 10MB
func readLimited(r io.Reader, maxSize int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxSize))
}

// apiJSONMaxBytes 限制所有元数据 API 返回的 JSON 响应大小。
// 版本清单 / Loader 列表等接口本应返回几 KB ~ 几百 KB，
// 超过 10 MiB 基本就是恶意响应或错误页面，直接拒绝。
const apiJSONMaxBytes = 10 << 20

// readAPIJSON 读 resp.Body 并在 10 MiB 上限内 Unmarshal。
func readAPIJSON(resp *http.Response, v interface{}) error {
	body, err := readLimited(resp.Body, apiJSONMaxBytes)
	if err != nil {
		return err
	}
	if int64(len(body)) >= apiJSONMaxBytes {
		return fmt.Errorf("API 响应超过 %d 字节上限", apiJSONMaxBytes)
	}
	return json.Unmarshal(body, v)
}

// 安装器（Forge/NeoForge JAR）来自镜像、不受信任。其中的 install_profile.json /
// version.json 正常只有几百 KB，内嵌的库 jar 正常几十 MB。给条目读取设上限，
// 防止恶意安装器用高压缩比超大条目把进程内存撑爆（解压炸弹）。
const (
	maxInstallerJSONBytes int64 = 16 << 20  // 安装器内 JSON 元数据 16 MiB
	maxInstallerLibBytes  int64 = 256 << 20 // 安装器内内嵌库 jar 256 MiB
)

// readZipEntryLimited 读取单个 zip 条目并限制解压后体积：
// 先用 zip 元数据预检，再用 LimitReader 多读 1 字节判定实际超限，
// 调用方无需信任 f.UncompressedSize64 与真实流是否一致。
func readZipEntryLimited(f *zip.File, maxBytes int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(maxBytes) {
		return nil, fmt.Errorf("zip 条目解压后声明体积超过 %d 字节: %s", maxBytes, f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("zip 条目解压后体积超过 %d 字节: %s", maxBytes, f.Name)
	}
	return data, nil
}

// isSafeFileName 验证版本名/文件名只包含安全字符
// 防止路径遍历攻击（../, /, \ 等），只允许字母、数字、点、下划线、短横线
func isSafeFileName(name string) bool {
	if len(name) == 0 || len(name) > 100 {
		return false
	}
	for _, r := range name {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	// ASCII 白名单已经挡掉分隔符与冒号，但 CON / NUL / COM1 这类纯字母数字的
	// Windows 保留设备名仍能通过，统一复用 nameguard 的保留名判定再挡一道。
	if isReservedDeviceName(stemOfName(name)) {
		return false
	}
	return true
}

// isSafeRelPath 验证相对路径不包含路径遍历组件（Zip Slip 防护）
// 返回清洗后的安全路径，如果不安全返回空字符串
func isSafeRelPath(relPath string) string {
	if relPath == "" {
		return ""
	}
	cleaned := filepath.Clean(relPath)
	// 拒绝绝对路径
	if filepath.IsAbs(cleaned) {
		return ""
	}
	// 拒绝以 .. 开头的逃逸路径
	if strings.HasPrefix(cleaned, "..") {
		return ""
	}
	// 拒绝包含 .. 段的路径
	parts := strings.Split(cleaned, string(os.PathSeparator))
	for _, p := range parts {
		if p == ".." {
			return ""
		}
	}
	return cleaned
}

// ===== 日志功能 =====

// writeLog 将信息写入日志文件（用户可随时查看和复制）
func (a *App) writeLog(format string, args ...interface{}) {
	// 在写控制台 / qgl_install.log / 启动日志之前统一脱敏：启动参数与游戏输出里
	// 可能带微软 access token、Bearer、JWT、密码等，任何一处落盘/外发都算泄密。
	msg := sanitizeLogLine(fmt.Sprintf(format, args...))
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, msg)

	fmt.Print(logLine)

	mcDir := a.GetMinecraftDir()
	logPath := filepath.Join(mcDir, "qgl_install.log")
	// 有界日志：4MiB 软上限 + 单份 .1 轮转 + 拒符号链接，防止崩溃循环刷屏占满磁盘。
	_ = getBoundedLogger(logPath).appendBounded(logLine)

	if a.launchLogPath != "" {
		dir := filepath.Dir(a.launchLogPath)
		// 日志目录同样收权到 0700（已存在的宽权限目录一并收敛），失败则放弃本次日志落盘。
		if ensurePrivateDir(dir) == nil {
			_ = getBoundedLogger(a.launchLogPath).appendBounded(logLine)
		}
	}
}

// ===== 嵌入 bangbang93 ForgeInstaller =====

//go:embed resources/forge-installer.jar
var forgeInstallerJar []byte

// ===== 模组加载器相关结构体 =====

type LoaderInfo struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Version      string `json:"version"`
	MCVersion    string `json:"mcVersion"`
	DownloadURL  string `json:"downloadUrl"`
	IsInstalled  bool   `json:"isInstalled"`
	Stable       bool   `json:"stable"`
	Category     string `json:"category"`
	ForgeVersion string `json:"forgeVersion"`
	IsPreview    bool   `json:"isPreview"`
	Patch        string `json:"patch"`
	OptiFineType string `json:"optifineType"`
}

type BMCLAPIForgeEntry struct {
	Branch   string `json:"branch"`
	Modified string `json:"modified"`
	Version  string `json:"version"`
	Files    []struct {
		Category string `json:"category"`
		Format   string `json:"format"`
		Hash     string `json:"hash"`
		ID       int    `json:"id"`
		Size     int64  `json:"size"`
	} `json:"files"`
}

type BMCLAPIOptiFineEntry struct {
	MCVersion string `json:"mcversion"`
	Type      string `json:"type"`
	Patch     string `json:"patch"`
	Filename  string `json:"filename"`
	Forge     string `json:"forge"`
}

type FabricLoaderVersion struct {
	Separator string `json:"separator"`
	Build     int    `json:"build"`
	Version   string `json:"version"`
	Maven     string `json:"maven"`
	Stable    bool   `json:"stable"`
}

// ===== Forge 版本获取 =====

func (a *App) GetForgeVersions(mcVersion string) ([]LoaderInfo, error) {
	if !isValidMCVersion(mcVersion) {
		return nil, fmt.Errorf("无效的 Minecraft 版本格式")
	}

	apiURL := fmt.Sprintf("https://bmclapi2.bangbang93.com/forge/minecraft/%s", mcVersion)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Forge 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Forge 版本失败: HTTP %d", resp.StatusCode)
	}

	var entries []BMCLAPIForgeEntry
	if err := readAPIJSON(resp, &entries); err != nil {
		return nil, fmt.Errorf("解析 Forge 版本失败: %v", err)
	}

	recommendedVersion := ""
	if promosResp, promosErr := safeHTTPClient().Get("https://bmclapi2.bangbang93.com/forge/promos"); promosErr == nil && promosResp.StatusCode == http.StatusOK {
		var promos map[string]string
		if promosErr2 := readAPIJSON(promosResp, &promos); promosErr2 == nil {
			recommendedVersion = promos[mcVersion+"-recommended"]
		}
		promosResp.Body.Close()
	}

	loaders := []LoaderInfo{}
	for _, entry := range entries {
		var bestFile *struct {
			Category string `json:"category"`
			Format   string `json:"format"`
			Hash     string `json:"hash"`
			ID       int    `json:"id"`
			Size     int64  `json:"size"`
		}

		for i := range entry.Files {
			f := &entry.Files[i]
			if f.Category == "installer" && f.Format == "jar" {
				bestFile = f
				break
			}
			if f.Category == "universal" && bestFile == nil {
				bestFile = f
			}
		}

		if bestFile == nil && len(entry.Files) > 0 {
			bestFile = &entry.Files[0]
		}

		forgeVersion := mcVersion + "-" + entry.Version
		if entry.Branch != "" {
			forgeVersion += "-" + entry.Branch
		}

		category := "installer"
		if bestFile != nil {
			category = bestFile.Category
		}

		ext := "jar"
		if category == "universal" || category == "client" {
			ext = "zip"
		}
		downloadURL := fmt.Sprintf(
			"https://bmclapi2.bangbang93.com/maven/net/minecraftforge/forge/%s/forge-%s-%s.%s",
			forgeVersion, forgeVersion, category, ext,
		)

		isRecommended := entry.Version == recommendedVersion

		loaders = append(loaders, LoaderInfo{
			Name:         "forge",
			DisplayName:  "Forge",
			Version:      entry.Version,
			MCVersion:    mcVersion,
			DownloadURL:  downloadURL,
			Stable:       isRecommended,
			Category:     category,
			ForgeVersion: forgeVersion,
		})
	}

	return loaders, nil
}

// isValidMCVersion 验证 Minecraft 版本号格式
// 防止版本号注入攻击，只允许数字、点、下划线和字母
func isValidMCVersion(version string) bool {
	if len(version) > 20 {
		return false
	}
	for _, r := range version {
		if !((r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ===== Fabric 版本获取 =====

func (a *App) GetFabricVersions(mcVersion string) ([]LoaderInfo, error) {
	if !isValidMCVersion(mcVersion) {
		return nil, fmt.Errorf("无效的 Minecraft 版本格式")
	}

	client := safeHTTPClient()
	fabricMetaURL := "https://bmclapi2.bangbang93.com/fabric-meta/v2/versions"

	resp, err := client.Get(fabricMetaURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		resp, err = safeHTTPClient().Get("https://meta.fabricmc.net/v2/versions")
		if err != nil {
			return nil, fmt.Errorf("获取 Fabric 版本失败: %v", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Fabric 版本失败: HTTP %d", resp.StatusCode)
	}

	var fabricMeta struct {
		Game []struct {
			Version string `json:"version"`
			Stable  bool   `json:"stable"`
		} `json:"game"`
		Loader []FabricLoaderVersion `json:"loader"`
	}
	if err := readAPIJSON(resp, &fabricMeta); err != nil {
		return nil, fmt.Errorf("解析 Fabric 版本失败: %v", err)
	}

	mcVersionNormalized := mcVersion
	supported := false
	for _, g := range fabricMeta.Game {
		if g.Version == mcVersionNormalized {
			supported = true
			break
		}
	}
	if !supported {
		return []LoaderInfo{}, nil
	}

	loaders := []LoaderInfo{}
	for _, lv := range fabricMeta.Loader {
		loaders = append(loaders, LoaderInfo{
			Name:        "fabric",
			DisplayName: "Fabric",
			Version:     lv.Version,
			MCVersion:   mcVersion,
			DownloadURL: "",
			Stable:      lv.Stable,
		})
	}

	return loaders, nil
}

// ===== NeoForge 版本获取 =====

func (a *App) GetNeoForgeVersions(mcVersion string) ([]LoaderInfo, error) {
	if !isValidMCVersion(mcVersion) {
		return nil, fmt.Errorf("无效的 Minecraft 版本格式")
	}

	major, minor, patch := parseMCVersion(mcVersion)
	mcNum := major*1000 + minor*100 + patch
	if mcNum < 1201 {
		return []LoaderInfo{}, nil
	}

	var allVersions []string

	legacyURL := "https://bmclapi2.bangbang93.com/neoforge/meta/api/maven/details/releases/net/neoforged/forge"
	if entries, err := fetchNeoForgeVersionList(legacyURL); err == nil {
		allVersions = append(allVersions, entries...)
	}

	latestURL := "https://bmclapi2.bangbang93.com/neoforge/meta/api/maven/details/releases/net/neoforged/neoforge"
	if entries, err := fetchNeoForgeVersionList(latestURL); err == nil {
		allVersions = append(allVersions, entries...)
	}

	if len(allVersions) == 0 {
		legacyOfficialURL := "https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/forge"
		if entries, err := fetchNeoForgeVersionList(legacyOfficialURL); err == nil {
			allVersions = append(allVersions, entries...)
		}
		latestOfficialURL := "https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/neoforge"
		if entries, err := fetchNeoForgeVersionList(latestOfficialURL); err == nil {
			allVersions = append(allVersions, entries...)
		}
	}

	loaders := []LoaderInfo{}
	for _, apiName := range allVersions {
		isLegacy := strings.Contains(apiName, "1.20.1")
		inheritVersion := ""

		if isLegacy {
			inheritVersion = "1.20.1"
		} else {
			versionPart := apiName
			if idx := strings.Index(apiName, "-"); idx > 0 {
				versionPart = apiName[:idx]
			}
			parts := strings.Split(versionPart, ".")
			if len(parts) >= 2 {
				nfMajor := parts[0]
				nfMinor := parts[1]
				if nfMinor == "0" {
					inheritVersion = "1." + nfMajor
				} else {
					inheritVersion = "1." + nfMajor + "." + nfMinor
				}
			}
		}

		if inheritVersion != mcVersion {
			continue
		}

		isBeta := strings.Contains(apiName, "beta")

		if apiName == "1.20.1-47.1.82" {
			continue
		}

		pkgName := "neoforge"
		if isLegacy {
			pkgName = "forge"
		}

		downloadURL := fmt.Sprintf(
			"https://bmclapi2.bangbang93.com/maven/net/neoforged/%s/%s/%s-%s-installer.jar",
			pkgName, apiName, pkgName, apiName,
		)

		displayVersion := apiName
		if isLegacy {
			displayVersion = strings.TrimPrefix(apiName, "1.20.1-")
		}

		loaders = append(loaders, LoaderInfo{
			Name:         "neoforge",
			DisplayName:  "NeoForge",
			Version:      displayVersion,
			MCVersion:    mcVersion,
			DownloadURL:  downloadURL,
			Stable:       !isBeta,
			ForgeVersion: apiName,
		})
	}

	if len(loaders) > 10 {
		loaders = loaders[len(loaders)-10:]
	}

	return loaders, nil
}

func fetchNeoForgeVersionList(apiURL string) ([]string, error) {
	if !isHTTPSURL(apiURL) {
		return nil, fmt.Errorf("不安全的 URL 协议")
	}

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := readLimited(resp.Body, apiJSONMaxBytes)
	if err != nil {
		return nil, err
	}

	var data struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(body, &data); err == nil && len(data.Versions) > 0 {
		return data.Versions, nil
	}

	var mavenData struct {
		Versions struct {
			Version []string `json:"version"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &mavenData); err == nil && len(mavenData.Versions.Version) > 0 {
		return mavenData.Versions.Version, nil
	}

	return nil, fmt.Errorf("无法解析版本列表")
}

// ===== OptiFine 版本获取 =====

func (a *App) GetOptiFineVersions(mcVersion string) ([]LoaderInfo, error) {
	if !isValidMCVersion(mcVersion) {
		return nil, fmt.Errorf("无效的 Minecraft 版本格式")
	}

	client := safeHTTPClient()
	apiURL := "https://bmclapi2.bangbang93.com/optifine/versionList"

	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 OptiFine 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 OptiFine 版本失败: HTTP %d", resp.StatusCode)
	}

	var allEntries []BMCLAPIOptiFineEntry
	if err := readAPIJSON(resp, &allEntries); err != nil {
		return nil, fmt.Errorf("解析 OptiFine 版本失败: %v", err)
	}

	loaders := []LoaderInfo{}
	for _, entry := range allEntries {
		if entry.MCVersion != mcVersion {
			continue
		}

		versionName := entry.Type + "_" + entry.Patch

		downloadURL := fmt.Sprintf(
			"https://bmclapi2.bangbang93.com/optifine/%s/%s/%s",
			entry.MCVersion, entry.Type, entry.Patch,
		)

		isPreview := strings.HasPrefix(entry.Filename, "preview_")

		loaders = append(loaders, LoaderInfo{
			Name:         "optifine",
			DisplayName:  "OptiFine",
			Version:      versionName,
			MCVersion:    mcVersion,
			DownloadURL:  downloadURL,
			Stable:       !isPreview,
			IsPreview:    isPreview,
			Patch:        entry.Patch,
			OptiFineType: entry.Type,
		})
	}

	return loaders, nil
}

// ===== 加载器安装 =====

func (a *App) extractForgeInstaller() (string, error) {
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	cacheDir := filepath.Join(tempDir, "qgl_cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", fmt.Errorf("创建缓存目录失败: %v", err)
	}

	installerPath := filepath.Join(cacheDir, "forge_installer.jar")

	if info, err := os.Stat(installerPath); err == nil && info.Size() == int64(len(forgeInstallerJar)) {
		return installerPath, nil
	}

	// 安装器 jar 走原子私有写：避免进程在落盘途中崩溃留下半截 jar，并拒绝沿既有
	// 符号链接把安装器写到缓存目录外。
	if err := secureWritePrivateFile(installerPath, forgeInstallerJar); err != nil {
		return "", fmt.Errorf("提取 ForgeInstaller 失败: %w", err)
	}

	return installerPath, nil
}

func isOldForge(versionStr string) bool {
	parts := strings.Split(versionStr, "-")
	verPart := parts[len(parts)-1]
	majorStr := strings.Split(verPart, ".")[0]
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return false
	}
	return major < 20
}

func (a *App) InstallForge(mcVersion string, forgeVersion string) error {
	if !isValidMCVersion(mcVersion) {
		return fmt.Errorf("无效的 Minecraft 版本格式")
	}
	if !isSafeFileName(forgeVersion) {
		return fmt.Errorf("无效的 Forge 版本格式")
	}

	a.writeLog("========== 开始安装 Forge: MC=%s, Forge=%s ==========", mcVersion, forgeVersion)

	fullVersion := forgeVersion
	if !strings.Contains(forgeVersion, mcVersion) {
		fullVersion = mcVersion + "-" + forgeVersion
	}
	a.writeLog("完整版本号: %s", fullVersion)

	mcDir := a.GetMinecraftDir()
	a.writeLog(".minecraft 目录: %s", mcDir)

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	installerPath := filepath.Join(tempDir, fmt.Sprintf("forge-%s-installer.jar", fullVersion))

	a.emitProgress("downloading", "下载 Forge 安装器", 0, 0)

	downloadURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/maven/net/minecraftforge/forge/%s/forge-%s-installer.jar",
		fullVersion, fullVersion,
	)
	a.writeLog("下载 URL: %s", downloadURL)

	os.Remove(installerPath)

	if err := a.downloadFile(downloadURL, installerPath, true); err != nil {
		a.writeLog("下载 Forge 安装器失败: %v", err)
		return fmt.Errorf("下载 Forge 安装器失败: %v", err)
	}

	if info, err := os.Stat(installerPath); err == nil {
		a.writeLog("安装器文件大小: %d 字节", info.Size())
	}

	isOld := isOldForge(fullVersion)
	a.writeLog("是否为旧版 Forge (<20): %v", isOld)

	if isOld {
		a.emitProgress("downloading", "安装旧版 Forge", 0, 0)
		return a.installOldForge(installerPath, mcDir, mcVersion)
	}

	a.emitProgress("downloading", "分析 Forge 支持库", 0, 0)

	if err := a.downloadForgeLibraries(installerPath, mcDir, mcVersion); err != nil {
		a.writeLog("下载 Forge 支持库失败（将继续尝试安装）: %v", err)
	}

	a.ensureLauncherProfiles(mcDir)

	oldVersions := a.getVersionFolderList(mcDir)

	a.emitProgress("downloading", "运行 Forge 安装器", 0, 0)

	err := a.runForgeInstaller(installerPath, mcDir)
	if err != nil {
		return err
	}

	newVersionFolder := a.findNewVersionFolder(mcDir, oldVersions, mcVersion, "forge")
	if newVersionFolder == "" {
		return fmt.Errorf("Forge 安装器运行完成但未找到版本文件夹")
	}

	if !a.validateVersionInstallation(newVersionFolder) {
		os.RemoveAll(newVersionFolder)
		return fmt.Errorf("Forge 安装验证失败：版本 JSON 无效")
	}

	fmt.Printf("Forge 安装成功: %s\n", filepath.Base(newVersionFolder))

	os.Remove(installerPath)

	return nil
}

func (a *App) installOldForge(installerPath string, mcDir string, mcVersion string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return fmt.Errorf("打开 Forge 安装器失败: %v", err)
	}
	defer r.Close()

	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				return fmt.Errorf("读取 install_profile.json 失败: %v", err)
			}
			if err := json.Unmarshal(data, &installProfile); err != nil {
				return fmt.Errorf("解析 install_profile.json 失败: %v", err)
			}
			break
		}
	}

	if installProfile == nil {
		return fmt.Errorf("安装器中未找到 install_profile.json")
	}

	targetVersion := ""
	if id, ok := installProfile["id"].(string); ok && id != "" {
		targetVersion = id
	}
	if targetVersion == "" {
		targetVersion = mcVersion + "-forge-unknown"
	}

	versionFolder := filepath.Join(mcDir, "versions", targetVersion)

	if err := os.MkdirAll(versionFolder, 0700); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}

	if installProfile["install"] == nil {
		jsonPath, _ := installProfile["json"].(string)
		if jsonPath == "" {
			return fmt.Errorf("install_profile.json 中缺少 json 字段")
		}
		// Zip Slip 防护：验证 ZIP 内路径不逃逸
		jsonPath = strings.TrimPrefix(jsonPath, "/")
		safeJSONPath := isSafeRelPath(jsonPath)
		if safeJSONPath == "" {
			return fmt.Errorf("安装器中 JSON 路径不安全: %s", jsonPath)
		}

		var versionJSONData []byte
		for _, f := range r.File {
			if f.Name == safeJSONPath {
				data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
				if err != nil {
					return fmt.Errorf("读取版本 JSON 失败: %v", err)
				}
				versionJSONData = data
				break
			}
		}

		if versionJSONData == nil {
			return fmt.Errorf("安装器中未找到 %s", safeJSONPath)
		}

		var versionJSON map[string]interface{}
		if err := json.Unmarshal(versionJSONData, &versionJSON); err != nil {
			return fmt.Errorf("解析版本 JSON 失败: %v", err)
		}
		versionJSON["id"] = targetVersion
		if versionJSON["inheritsFrom"] == nil {
			versionJSON["inheritsFrom"] = mcVersion
		}

		jsonFilePath := filepath.Join(versionFolder, targetVersion+".json")
		// 复用安装包 JSON 的 16MiB 读取上限作为落盘上限：输出来自该安装包，体积只会更小；
		// 走有界原子私有写，Marshal/超量/落盘任一失败都返回，不再吞错或留下半截文件。
		if err := writePrivateJSONBounded(jsonFilePath, versionJSON, maxInstallerJSONBytes); err != nil {
			return fmt.Errorf("保存版本 JSON 失败: %w", err)
		}

		r.Close()
		if err := a.extractMavenFiles(installerPath, mcDir); err != nil {
			fmt.Printf("解压 maven 文件失败（可能不影响启动）: %v\n", err)
		}
	} else {
		installInfo := installProfile["install"].(map[string]interface{})
		filePath, _ := installInfo["filePath"].(string)
		pathStr, _ := installInfo["path"].(string)

		if pathStr != "" && filePath != "" {
			// Zip Slip 防护：安装器给出的 Maven 路径与 zip 内条目名均走严格
			// 正斜杠相对路径白名单（拒盘符、反斜杠、冒号、保留设备名、.. 段）。
			safePathStr := SafeMavenRelPath(pathStr)
			safeFilePath := SafeMavenRelPath(filePath)
			if safePathStr == "" || safeFilePath == "" {
				return fmt.Errorf("安装器中路径不安全，跳过")
			}
			libPath := filepath.Join(mcDir, "libraries", filepath.FromSlash(safePathStr))
			// 内嵌库用 os.OpenFile 直接落盘，必须先确保父目录存在且收权 0700；
			// 原先忽略 MkdirAll 错误会让随后的 OpenFile 报一个更难定位的失败。
			if err := ensurePrivateDir(filepath.Dir(libPath)); err != nil {
				return fmt.Errorf("创建安装器内嵌库目录失败: %w", err)
			}

			for _, f := range r.File {
				if f.Name == safeFilePath {
					if f.UncompressedSize64 > uint64(maxInstallerLibBytes) {
						return fmt.Errorf("安装器内嵌库过大(解压炸弹防护): %s", safeFilePath)
					}
					// 内嵌库同样拒绝符号链接 / 设备等特殊条目，只允许普通文件落盘。
					if f.Mode()&unsafeEntryMode != 0 {
						return fmt.Errorf("安装器内嵌库是不允许的特殊类型: %s", safeFilePath)
					}
					rc, err := f.Open()
					if err != nil {
						break
					}
					out, err := os.OpenFile(libPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
					if err != nil {
						rc.Close()
						break
					}
					n, copyErr := io.Copy(out, io.LimitReader(rc, maxInstallerLibBytes+1))
					out.Close()
					rc.Close()
					if copyErr != nil || n > maxInstallerLibBytes {
						os.Remove(libPath)
						return fmt.Errorf("安装器内嵌库超过 %d 字节上限(解压炸弹防护): %s", maxInstallerLibBytes, safeFilePath)
					}
					break
				}
			}
		}

		versionInfo := installProfile["versionInfo"]
		if versionInfo != nil {
			vi := versionInfo.(map[string]interface{})
			vi["id"] = targetVersion
			if vi["inheritsFrom"] == nil {
				vi["inheritsFrom"] = mcVersion
			}
			jsonFilePath := filepath.Join(versionFolder, targetVersion+".json")
			// 旧版 Forge 分支此前完全忽略序列化与落盘错误且为非原子写，统一收口到
			// 有界原子私有写，任一失败都向上返回（安装后续会校验，避免带病继续）。
			if err := writePrivateJSONBounded(jsonFilePath, vi, maxInstallerJSONBytes); err != nil {
				return fmt.Errorf("保存版本 JSON 失败: %w", err)
			}
		}
	}

	if !a.validateVersionInstallation(versionFolder) {
		os.RemoveAll(versionFolder)
		return fmt.Errorf("旧版 Forge 安装验证失败")
	}

	fmt.Printf("旧版 Forge 安装成功: %s\n", targetVersion)

	os.Remove(installerPath)

	return nil
}

// Forge/NeoForge 安装器是从镜像下载的不受信任 JAR，其中 maven/ 条目会被
// 解压到 libraries。统一走 zipextract 安全解压内核：Zip Slip、符号链接等特殊
// 条目、条目数 / 单条目 / 总量上限全部预检，落盘采用临时文件 + 原子替换。
// 正常的依赖 jar 只有几 MB 到几十 MB，正常数据永远碰不到这些阈值。
const (
	maxMavenEntryBytes int64 = 256 << 20 // 单个 maven 条目 256 MiB
	maxMavenTotalBytes int64 = 2 << 30   // maven 解压总量 2 GiB
	maxMavenEntries          = 100000    // maven 条目数上限（inode 耗尽防护）
)

func (a *App) extractMavenFiles(installerPath string, mcDir string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return err
	}
	defer r.Close()

	libsDir := filepath.Join(mcDir, "libraries")
	lim := zipExtractLimits{
		EntryMax:   maxMavenEntryBytes,
		TotalMax:   maxMavenTotalBytes,
		MaxEntries: maxMavenEntries,
	}
	n, count, err := extractZipPrefixes(r.File, libsDir, []string{"maven/"}, lim, a.writeLog)
	if err != nil {
		return err
	}
	a.writeLog("maven 解压完成: %d 个文件，共 %d 字节", count, n)
	return nil
}

func (a *App) downloadForgeLibraries(installerPath string, mcDir string, mcVersion string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return fmt.Errorf("打开安装器失败: %v", err)
	}
	defer r.Close()

	var profileData, versionData map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" || f.Name == "version.json" {
			// 安装器 JSON 不受信任，限 16 MiB 防解压炸弹；超限/损坏就跳过该文件。
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				fmt.Printf("跳过安装器条目 %s: %v\n", f.Name, err)
				continue
			}
			var target map[string]interface{}
			if err := json.Unmarshal(data, &target); err != nil {
				continue
			}
			if f.Name == "install_profile.json" {
				profileData = target
			} else {
				versionData = target
			}
		}
	}

	if profileData == nil {
		return fmt.Errorf("未找到 install_profile.json")
	}

	var allLibs []interface{}
	if libs, ok := profileData["libraries"].([]interface{}); ok {
		allLibs = append(allLibs, libs...)
	}
	if versionData != nil {
		if libs, ok := versionData["libraries"].([]interface{}); ok {
			allLibs = append(allLibs, libs...)
		}
	}

	libsDir := filepath.Join(mcDir, "libraries")
	for _, lib := range allLibs {
		libMap, ok := lib.(map[string]interface{})
		if !ok {
			continue
		}

		downloads, ok := libMap["downloads"].(map[string]interface{})
		if !ok {
			continue
		}

		artifact, ok := downloads["artifact"].(map[string]interface{})
		if !ok {
			continue
		}

		url, _ := artifact["url"].(string)
		path, _ := artifact["path"].(string)
		sha1, _ := artifact["sha1"].(string)
		if url == "" || path == "" {
			continue
		}

		// 安装器不可信：库 URL 必须落在官方/可信 Maven 主机白名单内，
		// 否则攻击者可借安装器把任意 jar 拉进 classpath（供应链 RCE）。
		if !isAllowedMavenLibURL(url) {
			fmt.Printf("跳过非可信 Maven 主机的库（防止供应链投毒）: %s\n", url)
			continue
		}

		url = rewriteMavenLibURLToBMCL(url)

		// Zip Slip 防护：库路径走严格 Maven 相对路径白名单
		safePath := SafeMavenRelPath(path)
		if safePath == "" {
			fmt.Printf("跳过不安全的库路径: %s\n", path)
			continue
		}
		destPath := filepath.Join(libsDir, filepath.FromSlash(safePath))

		// 走带官方 sha1 的下载：已存在的库也会经侧车摘要链复核，
		// 避免“文件在就直接信任”导致被替换的 jar 被加载。
		// 个别安装器确实缺 sha1 字段时仍下载（主机已白名单），但不再自行跳过校验。
		if err := a.downloadVerifiedFile(url, destPath, strings.TrimSpace(sha1), false); err != nil {
			fmt.Printf("下载/校验支持库失败 %s: %v\n", path, err)
		}
	}

	dataSection, hasData := profileData["data"].(map[string]interface{})
	if !hasData {
		fmt.Printf("未找到 data 字段（跳过 Mappings 下载）\n")
	} else if _, hasMojmaps := dataSection["MOJMAPS"]; hasMojmaps {
		fmt.Printf("检测到新版 Forge，需要下载 Mappings 文件\n")
		a.downloadForgeMappings(mcDir, mcVersion, installerPath)
	} else {
		fmt.Printf("未找到 MOJMAPS 字段（跳过 Mappings 下载）\n")
	}

	return nil
}

// ensureForgeMappings 确保 Forge 新版需要的 Mappings 文件存在
// 安全修复：移除 PowerShell 命令，改用 Go 原生 HTTP 下载，防止命令注入
// maxMappingsDownloadBytes 限制 Forge mappings 下载体积为 1 GiB，正常映射文件只有十几 MB，只有明显炸磁盘的响应才会触发。
const maxMappingsDownloadBytes int64 = 1 << 30

func (a *App) ensureForgeMappings(installerPath string, mcDir string) {
	a.writeLog("===== 开始检查 Forge Mappings 文件 =====")

	r, err := zip.OpenReader(installerPath)
	if err != nil {
		a.writeLog("无法打开安装器（跳过 Mappings 检查）: %v", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	var mcVersion string
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				a.writeLog("读取 install_profile.json 失败(条目过大或损坏，跳过): %v", err)
				break
			}
			json.Unmarshal(data, &installProfile)

			if minecraftVal, ok := installProfile["minecraft"]; ok {
				if mv, ok := minecraftVal.(string); ok {
					mcVersion = mv
					a.writeLog("找到 mcVersion: %s", mcVersion)
				}
			}
			break
		}
	}

	if installProfile == nil || mcVersion == "" {
		a.writeLog("未找到 mcVersion（跳过 Mappings 检查）")
		return
	}

	dataSection, ok := installProfile["data"].(map[string]interface{})
	if !ok {
		a.writeLog("未找到 data 字段（跳过 Mappings 检查）")
		return
	}

	mojmapsData, ok := dataSection["MOJMAPS"].(map[string]interface{})
	if !ok {
		a.writeLog("未找到 MOJMAPS 字段（跳过 Mappings 检查）")
		return
	}

	clientValue, ok := mojmapsData["client"].(string)
	if !ok || clientValue == "" {
		a.writeLog("未找到 MOJMAPS.client 字段（跳过 Mappings 检查）")
		return
	}

	clientValue = strings.Trim(clientValue, "[]")
	atIndex := strings.Index(clientValue, "@")
	if atIndex == -1 {
		a.writeLog("MOJMAPS.client 格式错误（跳过 Mappings 检查）")
		return
	}

	originalName := clientValue[:atIndex]
	extension := clientValue[atIndex+1:]

	// 坐标与扩展名来自不可信的安装器 JSON，不能再用 Split 后原样拼 filepath.Join，
	// 否则 ".." 段 / 分隔符 / 带穿越的扩展名会把 mappings 写到 libraries 之外。
	// 统一走严格白名单推导，并强制结果落在 <mcDir>/libraries 内。
	targetPath, ok := SafeMojmapsMappingsPath(mcDir, originalName, extension)
	if !ok {
		a.writeLog("MOJMAPS.client 坐标或扩展名未通过路径白名单（跳过 Mappings 检查）")
		return
	}

	a.writeLog("目标路径: %s", targetPath)

	if _, err := os.Stat(targetPath); err == nil {
		a.writeLog("Mappings 文件已存在: %s", targetPath)
		return
	}

	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	var rawJSON map[string]interface{}
	if err := readLocalJSONBounded(jsonPath, &rawJSON, 0, "原版版本 JSON"); err != nil {
		a.writeLog("无法读取/解析原版版本 JSON: %v", err)
		return
	}

	downloads, _ := rawJSON["downloads"].(map[string]interface{})
	if downloads == nil {
		a.writeLog("未找到 downloads 字段")
		return
	}

	clientMappings, _ := downloads["client_mappings"].(map[string]interface{})
	if clientMappings == nil {
		a.writeLog("未找到 client_mappings 字段")
		return
	}

	mappingsURL, _ := clientMappings["url"].(string)
	if mappingsURL == "" {
		a.writeLog("未找到 client_mappings URL")
		return
	}

	// 安全验证：只允许 HTTPS
	if !isHTTPSURL(mappingsURL) {
		a.writeLog("跳过不安全的下载 URL（非 HTTPS）: %s", mappingsURL)
		return
	}

	mappingsURL = rewriteMappedDataURLToBMCL(mappingsURL)

	a.writeLog("使用 Go 原生 HTTP 下载 Mappings 文件...")
	a.writeLog("下载 URL: %s", mappingsURL)
	a.writeLog("保存到: %s", targetPath)

	// 这里是手写流式下载（os.OpenFile 直接落盘），由本处显式确保目录 0700 并收权。
	if err := ensurePrivateDir(filepath.Dir(targetPath)); err != nil {
		a.writeLog("创建目标目录失败: %v", err)
		return
	}

	// 安全修复：使用 Go 原生 HTTP 下载，替代 PowerShell 命令，防止命令注入
	client := safeHTTPClient()
	req, err := http.NewRequest("GET", mappingsURL, nil)
	if err != nil {
		a.writeLog("创建下载请求失败: %v", err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		a.writeLog("下载失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.writeLog("下载失败: HTTP %d", resp.StatusCode)
		return
	}

	out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		a.writeLog("创建目标文件失败: %v", err)
		return
	}
	defer out.Close()

	limited := io.LimitReader(resp.Body, maxMappingsDownloadBytes+1)
	n, copyErr := io.Copy(out, limited)
	if copyErr != nil || n > maxMappingsDownloadBytes {
		a.writeLog("mappings 文件超过 %d 字节上限，中止下载", maxMappingsDownloadBytes)
		os.Remove(targetPath)
		return
	}

	fileInfo, statErr := os.Stat(targetPath)
	if statErr != nil {
		a.writeLog("下载后验证文件失败: %v", statErr)
		return
	}

	if fileInfo.Size() == 0 {
		a.writeLog("下载的文件为空！删除空文件")
		os.Remove(targetPath)
		return
	}

	a.writeLog("Mappings 下载成功! 文件大小: %d 字节, 路径: %s", fileInfo.Size(), targetPath)
}

func (a *App) downloadForgeMappings(mcDir string, mcVersion string, installerPath string) {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		fmt.Printf("无法打开安装器（跳过 Mappings 下载）: %v\n", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				fmt.Printf("读取 install_profile.json 失败(条目过大或损坏，跳过): %v\n", err)
				break
			}
			json.Unmarshal(data, &installProfile)
			break
		}
	}

	if installProfile == nil {
		fmt.Printf("未找到 install_profile.json（跳过 Mappings 下载）\n")
		return
	}

	dataSection, ok := installProfile["data"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 data 字段（跳过 Mappings 下载）\n")
		return
	}

	mojmapsData, ok := dataSection["MOJMAPS"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 MOJMAPS 字段（跳过 Mappings 下载）\n")
		return
	}

	mcpVersion, ok := mojmapsData["version"].(string)
	if !ok || mcpVersion == "" {
		fmt.Printf("未找到 MOJMAPS.version 字段（跳过 Mappings 下载）\n")
		return
	}

	fmt.Printf("检测到 Forge MOJMAPS: %s\n", mcpVersion)

	targetPath, ok := SafeMappingsVersionPath(mcDir, mcpVersion)
	if !ok {
		fmt.Printf("MOJMAPS.version 未通过落盘路径白名单（跳过 Mappings 下载）: %s\n", mcpVersion)
		return
	}

	if _, err := os.Stat(targetPath); err == nil {
		fmt.Printf("Mappings 文件已存在: %s\n", targetPath)
		return
	}

	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	var rawJSON map[string]interface{}
	if err := readLocalJSONBounded(jsonPath, &rawJSON, 0, "原版版本 JSON"); err != nil {
		fmt.Printf("无法读取/解析原版版本 JSON（跳过 Mappings 下载）: %v\n", err)
		return
	}

	downloads, ok := rawJSON["downloads"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 downloads 字段（跳过 Mappings 下载）\n")
		return
	}

	clientMappings, ok := downloads["client_mappings"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 client_mappings 字段（跳过 Mappings 下载）\n")
		return
	}

	mappingsURL, _ := clientMappings["url"].(string)
	if mappingsURL == "" {
		fmt.Printf("未找到 client_mappings URL（跳过 Mappings 下载）\n")
		return
	}

	if !isHTTPSURL(mappingsURL) {
		fmt.Printf("跳过不安全的下载 URL（非 HTTPS）: %s\n", mappingsURL)
		return
	}

	mappingsURL = rewriteMappedDataURLToBMCL(mappingsURL)

	tempPath := targetPath + ".tmp"
	_ = os.Remove(tempPath)
	fmt.Printf("下载 Forge Mappings (%s): %s\n", mcpVersion, mappingsURL)
	if err := a.downloadFileBounded(mappingsURL, tempPath, false, maxMappingsDownloadBytes); err != nil {
		os.Remove(tempPath)
		fmt.Printf("下载 Mappings 失败: %v\n", err)
		return
	}

	if err := os.Rename(tempPath, targetPath); err != nil {
		os.Remove(tempPath)
		fmt.Printf("重命名 Mappings 文件失败: %v\n", err)
		return
	}

	fmt.Printf("Mappings 下载成功: %s\n", targetPath)
}

func (a *App) ensureLauncherProfiles(mcDir string) {
	profilesPath := filepath.Join(mcDir, "launcher_profiles.json")
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		profiles := map[string]interface{}{
			"profiles": map[string]interface{}{},
		}
		// launcher_profiles.json 是启动器状态文件，有界原子私有写防半截写与符号链接写穿；
		// 序列化错误也不再被丢弃。
		if err := writePrivateJSON(profilesPath, profiles); err != nil {
			fmt.Printf("创建 launcher_profiles.json 失败: %v\n", err)
		}
	}
}

func (a *App) getVersionFolderList(mcDir string) map[string]bool {
	versionsDir := filepath.Join(mcDir, "versions")
	result := map[string]bool{}

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if entry.IsDir() {
			result[entry.Name()] = true
		}
	}

	return result
}

func (a *App) runForgeInstaller(installerPath string, mcDir string) error {
	a.writeLog("===== 开始运行 ForgeInstaller =====")

	a.ensureForgeMappings(installerPath, mcDir)

	bbInstallerPath, err := a.extractForgeInstaller()
	if err != nil {
		a.writeLog("提取 ForgeInstaller 失败: %v", err)
		return err
	}
	a.writeLog("ForgeInstaller 路径: %s", bbInstallerPath)
	a.writeLog("Forge 安装器路径: %s", installerPath)

	javaEntry, err := a.selectJavaForInstaller()
	if err != nil {
		a.writeLog("选择 Java 失败: %v", err)
		return fmt.Errorf("选择 Java 失败: %v", err)
	}
	a.writeLog("使用 Java: %s (版本: %s, 主版本: %d)", javaEntry.Path, javaEntry.Version, javaEntry.MajorVer)

	classpath := bbInstallerPath + ";" + installerPath

	args := []string{}
	if javaEntry.MajorVer >= 9 {
		args = append(args, "--add-exports", "cpw.mods.bootstraplauncher/cpw.mods.bootstraplauncher=ALL-UNNAMED")
	}
	args = append(args, "-cp", classpath, "com.bangbang93.ForgeInstaller", mcDir)

	a.writeLog("完整命令: %s %s", javaEntry.Path, strings.Join(args, " "))

	// 启动前对安装器 JVM 做目标审计：java 可执行、工作目录、绝对 classpath 的目录归属
	// （bbInstaller / installer 各自的父目录 + mcDir）、主类与程序参数，阻止任何指向
	// UNC / 目录穿越 / 允许目录之外的 jar/classpath。
	forgeRoots := []string{mcDir, filepath.Dir(bbInstallerPath), filepath.Dir(installerPath)}
	forgeAudit := AuditExternalJVM(ExternalJVMPlan{
		JavaExe:      javaEntry.Path,
		WorkDir:      mcDir,
		Classpath:    []string{bbInstallerPath, installerPath},
		MainClass:    "com.bangbang93.ForgeInstaller",
		ProgramArgs:  []string{mcDir},
		AllowedRoots: forgeRoots,
	})
	if forgeAudit.HasCritical() {
		return fmt.Errorf("Forge 安装器启动审计未通过: %s", forgeAudit.FirstCriticalCode())
	}

	cmd := exec.Command(javaEntry.Path, args...)
	cmd.Dir = mcDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Forge 安装器本身是个独立 JVM：不下发净化环境就会继承
	// JAVA_TOOL_OPTIONS 一族，绕过 JVM 参数过滤注入 javaagent。
	a.applySanitizedJVMEnv(cmd, "ForgeInstaller", nil)

	output, runErr := cmd.CombinedOutput()
	outputStr := string(output)

	a.writeLog("----- ForgeInstaller 输出开始 -----")
	if outputStr != "" {
		for _, line := range strings.Split(outputStr, "\n") {
			a.writeLog("  %s", line)
		}
	} else {
		a.writeLog("  (无输出)")
	}
	a.writeLog("----- ForgeInstaller 输出结束 -----")
	if runErr != nil {
		a.writeLog("进程退出错误: %v", runErr)
	}

	lines := strings.Split(outputStr, "\n")
	var lastLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			lastLines = append(lastLines, line)
		}
	}

	foundTrue := false
	checkCount := 4
	if len(lastLines) < checkCount {
		checkCount = len(lastLines)
	}
	for _, line := range lastLines[len(lastLines)-checkCount:] {
		if line == "true" {
			foundTrue = true
			break
		}
	}

	if foundTrue {
		a.writeLog("检测到安装器成功标志 'true'，安装成功")
		return nil
	}

	a.writeLog("未检测到安装器成功标志 'true'，安装失败")

	if runErr != nil {
		errMsg := fmt.Errorf("Forge 安装器运行失败\nJava: %s (v%d)\n错误: %v\n\n完整输出:\n%s",
			javaEntry.Path, javaEntry.MajorVer, runErr, outputStr)
		a.writeLog("Forge 安装最终失败: %v", errMsg)
		return errMsg
	}

	errMsg := fmt.Errorf("Forge 安装器未返回成功标志\nJava: %s (v%d)\n\n完整输出:\n%s",
		javaEntry.Path, javaEntry.MajorVer, outputStr)
	a.writeLog("Forge 安装最终失败: %v", errMsg)
	return errMsg
}

func (a *App) findNewVersionFolder(mcDir string, oldVersions map[string]bool, mcVersion string, loaderType string) string {
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() || oldVersions[entry.Name()] {
			continue
		}
		name := entry.Name()
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, loaderType) && strings.Contains(nameLower, strings.ToLower(mcVersion)) {
			versionFolder := filepath.Join(versionsDir, name)
			if a.validateVersionInstallation(versionFolder) {
				return versionFolder
			}
		}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, loaderType) && strings.Contains(nameLower, strings.ToLower(mcVersion)) {
			versionFolder := filepath.Join(versionsDir, name)
			if a.validateVersionInstallation(versionFolder) {
				return versionFolder
			}
		}
	}

	return ""
}

func (a *App) InstallFabric(mcVersion string, loaderVersion string) error {
	if !isValidMCVersion(mcVersion) {
		return fmt.Errorf("无效的 Minecraft 版本格式")
	}
	if !isSafeFileName(loaderVersion) {
		return fmt.Errorf("无效的 Fabric Loader 版本格式")
	}

	mcDir := a.GetMinecraftDir()

	profileURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/fabric-meta/v2/versions/loader/%s/%s/profile/json",
		mcVersion, loaderVersion,
	)

	a.emitProgress("downloading", "获取 Fabric profile", 0, 0)

	client := safeHTTPClient()
	resp, err := client.Get(profileURL)
	if err != nil {
		return fmt.Errorf("获取 Fabric profile 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取 Fabric profile 失败: HTTP %d", resp.StatusCode)
	}

	var profileJSON map[string]interface{}
	if err := readAPIJSON(resp, &profileJSON); err != nil {
		return fmt.Errorf("解析 Fabric profile 失败: %v", err)
	}

	versionID := fmt.Sprintf("fabric-loader-%s-%s", loaderVersion, mcVersion)
	profileJSON["id"] = versionID

	versionDir := filepath.Join(mcDir, "versions", versionID)
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}

	jsonPath := filepath.Join(versionDir, versionID+".json")
	// 有界原子私有写：Marshal/超量/落盘任一失败都清理半成品并返回，不再原地截断写。
	if err := writePrivateJSON(jsonPath, profileJSON); err != nil {
		a.cleanupFailedInstallation(mcDir, versionID)
		return fmt.Errorf("保存版本 JSON 失败: %w", err)
	}

	a.emitProgress("downloading", "下载 Fabric 库文件", 0, 0)
	a.downloadFabricLibraries(profileJSON, mcDir)

	if !a.validateVersionInstallation(versionDir) {
		a.cleanupFailedInstallation(mcDir, versionID)
		return fmt.Errorf("Fabric 安装验证失败")
	}

	return nil
}

func (a *App) downloadFabricLibraries(profileJSON map[string]interface{}, mcDir string) {
	libsDir := filepath.Join(mcDir, "libraries")

	libs, ok := profileJSON["libraries"].([]interface{})
	if !ok {
		fmt.Printf("Fabric profile JSON 中没有 libraries 字段\n")
		return
	}

	downloadedCount := 0
	for _, libRaw := range libs {
		libMap, ok := libRaw.(map[string]interface{})
		if !ok {
			continue
		}

		downloads, ok := libMap["downloads"].(map[string]interface{})
		if !ok {
			continue
		}

		artifact, ok := downloads["artifact"].(map[string]interface{})
		if !ok {
			continue
		}

		url, _ := artifact["url"].(string)
		path, _ := artifact["path"].(string)
		if url == "" || path == "" {
			continue
		}

		// 供应链 RCE 防护（与 Forge 库一致）：profile JSON 不可信，artifact.url 可能被
		// 篡改指向攻击者自己的 https 服务器。先对“原始”主机做白名单校验（在镜像
		// 替换之前），拒绝非白名单主机 / userinfo / 非标端口，避免只校验 https scheme。
		if !isAllowedMavenLibURL(url) {
			fmt.Printf("跳过非信任主机的 Fabric 库 URL: %s\n", url)
			continue
		}

		sha1, _ := artifact["sha1"].(string)

		url = rewriteFabricLibURLToBMCL(url)

		// Zip Slip 防护：库路径走严格 Maven 相对路径白名单
		safePath := SafeMavenRelPath(path)
		if safePath == "" {
			fmt.Printf("跳过不安全的库路径: %s\n", path)
			continue
		}
		destPath := filepath.Join(libsDir, filepath.FromSlash(safePath))

		// 走带官方 sha1 锚点的下载（缺失时退化为侧车 UMFS/SHA512/SHA1 复核），
		// 已存在文件也会复核，杜绝“预置坏 jar + os.Stat 跳过”。
		if err := a.downloadVerifiedFile(url, destPath, strings.TrimSpace(sha1), false); err != nil {
			fmt.Printf("下载 Fabric 库失败 %s: %v\n", path, err)
		} else {
			downloadedCount++
		}
	}

	if downloadedCount > 0 {
		fmt.Printf("Fabric 库文件预下载完成: 成功下载 %d 个\n", downloadedCount)
	}
}

func (a *App) InstallNeoForge(mcVersion string, neoForgeVersion string) error {
	if !isValidMCVersion(mcVersion) {
		return fmt.Errorf("无效的 Minecraft 版本格式")
	}
	if !isSafeFileName(neoForgeVersion) {
		return fmt.Errorf("无效的 NeoForge 版本格式")
	}

	apiName := neoForgeVersion
	if !strings.Contains(neoForgeVersion, mcVersion+"-") && mcVersion == "1.20.1" {
		apiName = mcVersion + "-" + neoForgeVersion
	}

	mcDir := a.GetMinecraftDir()

	pkgName := "neoforge"
	if mcVersion == "1.20.1" {
		pkgName = "forge"
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	installerPath := filepath.Join(tempDir, fmt.Sprintf("neoforge-%s-installer.jar", apiName))

	a.emitProgress("downloading", "下载 NeoForge 安装器", 0, 0)

	downloadURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/maven/net/neoforged/%s/%s/%s-%s-installer.jar",
		pkgName, apiName, pkgName, apiName,
	)

	os.Remove(installerPath)

	if err := a.downloadFile(downloadURL, installerPath, true); err != nil {
		return fmt.Errorf("下载 NeoForge 安装器失败: %v", err)
	}

	a.emitProgress("downloading", "分析 NeoForge 支持库", 0, 0)
	if err := a.downloadForgeLibraries(installerPath, mcDir, mcVersion); err != nil {
		fmt.Printf("下载 NeoForge 支持库失败（将继续尝试安装）: %v\n", err)
	}

	a.ensureLauncherProfiles(mcDir)

	oldVersions := a.getVersionFolderList(mcDir)

	a.emitProgress("downloading", "运行 NeoForge 安装器", 0, 0)

	err := a.runForgeInstaller(installerPath, mcDir)
	if err != nil {
		return err
	}

	loaderType := "neoforge"
	if mcVersion == "1.20.1" {
		loaderType = "forge"
	}
	newVersionFolder := a.findNewVersionFolder(mcDir, oldVersions, mcVersion, loaderType)
	if newVersionFolder == "" {
		return fmt.Errorf("NeoForge 安装器运行完成但未找到版本文件夹")
	}

	if !a.validateVersionInstallation(newVersionFolder) {
		os.RemoveAll(newVersionFolder)
		return fmt.Errorf("NeoForge 安装验证失败：版本 JSON 无效")
	}

	fmt.Printf("NeoForge 安装成功: %s\n", filepath.Base(newVersionFolder))

	os.Remove(installerPath)

	return nil
}

func (a *App) InstallOptiFine(mcVersion string, optifineType string, optifinePatch string) error {
	if !isValidMCVersion(mcVersion) {
		return fmt.Errorf("无效的 Minecraft 版本格式")
	}
	if !isSafeFileName(optifineType) || !isSafeFileName(optifinePatch) {
		return fmt.Errorf("无效的 OptiFine 版本格式")
	}

	mcDir := a.GetMinecraftDir()

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	installerPath := filepath.Join(tempDir, fmt.Sprintf("OptiFine_%s_%s_%s.jar", mcVersion, optifineType, optifinePatch))

	a.emitProgress("downloading", "下载 OptiFine", 0, 0)

	downloadURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/optifine/%s/%s/%s",
		mcVersion, optifineType, optifinePatch,
	)

	os.Remove(installerPath)

	if err := a.downloadFile(downloadURL, installerPath, true); err != nil {
		return fmt.Errorf("下载 OptiFine 失败: %v", err)
	}

	javaEntry, err := a.selectJavaForInstaller()
	if err != nil {
		return fmt.Errorf("选择 Java 失败: %v", err)
	}

	a.ensureLauncherProfiles(mcDir)

	oldVersions := a.getVersionFolderList(mcDir)

	a.emitProgress("downloading", "运行 OptiFine 安装器", 0, 0)

	mcDirParent := filepath.Dir(mcDir)

	args := []string{}
	if javaEntry.MajorVer >= 9 {
		args = append(args, "--add-exports", "cpw.mods.bootstraplauncher/cpw.mods.bootstraplauncher=ALL-UNNAMED")
	}
	args = append(args, fmt.Sprintf("-Duser.home=%s", mcDirParent), "-cp", installerPath, "optifine.Installer")

	// 启动前审计 OptiFine 安装器 JVM：安装 jar 必须位于 mcDir 或其自身所在目录之内，
	// 阻止被 mcVersion/optifineType 等清单字段间接带到 UNC / 穿越 / 目录之外的 jar。
	ofAudit := AuditExternalJVM(ExternalJVMPlan{
		JavaExe:      javaEntry.Path,
		WorkDir:      mcDir,
		Classpath:    []string{installerPath},
		MainClass:    "optifine.Installer",
		AllowedRoots: []string{mcDir, filepath.Dir(installerPath)},
	})
	if ofAudit.HasCritical() {
		return fmt.Errorf("OptiFine 安装器启动审计未通过: %s", ofAudit.FirstCriticalCode())
	}

	cmd := exec.Command(javaEntry.Path, args...)
	cmd.Dir = mcDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// OptiFine 安装器同样是独立 JVM：净化环境并剥离隐式 JVM 参数变量，
	// APPDATA 仍按原需求指向 mcDir 的父目录（以 extra 覆盖方式安全注入）。
	a.applySanitizedJVMEnv(cmd, "OptiFineInstaller", map[string]string{
		"APPDATA": mcDirParent,
	})

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("安装 OptiFine 失败: %v\n输出: %s", err, string(output))
	}

	newVersionFolder := a.findNewVersionFolder(mcDir, oldVersions, mcVersion, "optifine")
	if newVersionFolder == "" {
		return fmt.Errorf("OptiFine 安装器运行完成但未找到版本文件夹")
	}

	if !a.validateVersionInstallation(newVersionFolder) {
		os.RemoveAll(newVersionFolder)
		return fmt.Errorf("OptiFine 安装验证失败：版本 JSON 无效")
	}

	fmt.Printf("OptiFine 安装成功: %s\n", filepath.Base(newVersionFolder))

	os.Remove(installerPath)

	return nil
}

// ===== 辅助函数 =====

func (a *App) validateVersionInstallation(versionFolder string) bool {
	if _, err := os.Stat(versionFolder); os.IsNotExist(err) {
		return false
	}

	jsonFiles, err := filepath.Glob(filepath.Join(versionFolder, "*.json"))
	if err != nil || len(jsonFiles) == 0 {
		return false
	}

	for _, jsonFile := range jsonFiles {
		var jsonData map[string]interface{}
		if err := readLocalJSONBounded(jsonFile, &jsonData, 0, "版本 JSON"); err != nil {
			continue
		}

		if jsonData["id"] == nil || jsonData["mainClass"] == nil {
			continue
		}

		return true
	}

	return false
}

func (a *App) cleanupFailedInstallation(mcDir string, versionID string) {
	versionFolder := filepath.Join(mcDir, "versions", versionID)

	if _, err := os.Stat(versionFolder); err == nil {
		os.RemoveAll(versionFolder)
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	forgeInstaller := filepath.Join(tempDir, fmt.Sprintf("forge-%s-installer.jar", versionID))
	if _, err := os.Stat(forgeInstaller); err == nil {
		os.Remove(forgeInstaller)
	}

	neoForgeInstaller := filepath.Join(tempDir, fmt.Sprintf("neoforge-%s-installer.jar", versionID))
	if _, err := os.Stat(neoForgeInstaller); err == nil {
		os.Remove(neoForgeInstaller)
	}

	optifineInstaller := filepath.Join(tempDir, fmt.Sprintf("OptiFine_%s*.jar", versionID))
	matches, _ := filepath.Glob(optifineInstaller)
	for _, m := range matches {
		os.Remove(m)
	}
}

func (a *App) CheckLoaderInstalled(mcVersion string, loaderName string) bool {
	mcDir := a.GetMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		switch loaderName {
		case "forge":
			if strings.Contains(name, "forge") && !strings.Contains(name, "neo") && strings.Contains(name, strings.ToLower(mcVersion)) {
				versionFolder := filepath.Join(versionsDir, entry.Name())
				return a.validateVersionInstallation(versionFolder)
			}
		case "fabric":
			if strings.Contains(name, "fabric") && strings.Contains(name, strings.ToLower(mcVersion)) {
				versionFolder := filepath.Join(versionsDir, entry.Name())
				return a.validateVersionInstallation(versionFolder)
			}
		case "neoforge":
			if (strings.Contains(name, "neoforge") || (strings.Contains(name, "forge") && strings.Contains(name, "1.20.1"))) && strings.Contains(name, strings.ToLower(mcVersion)) {
				versionFolder := filepath.Join(versionsDir, entry.Name())
				return a.validateVersionInstallation(versionFolder)
			}
		case "optifine":
			if strings.Contains(name, "optifine") && strings.Contains(name, strings.ToLower(mcVersion)) {
				versionFolder := filepath.Join(versionsDir, entry.Name())
				return a.validateVersionInstallation(versionFolder)
			}
		}
	}

	return false
}

func (a *App) AddLoaderToDownloadList(loaderName string, mcVersion string, loaderVersion string, downloadURL string) error {
	// 三个标识全部来自前端，最终拼进下载列表展示名并参与安装分发，必须收敛：
	// loaderName 走固定白名单（它决定后续 switch 分支），mc/loader 版本走严格名单段。
	loaderName = strings.ToLower(strings.TrimSpace(loaderName))
	switch loaderName {
	case "forge", "fabric", "neoforge", "optifine":
	default:
		return fmt.Errorf("不支持的加载器类型: %s", loaderName)
	}
	safeMC, whyM := SafeVersionComponent(mcVersion)
	if whyM != nameRejectNone {
		return fmt.Errorf("Minecraft 版本无效: %s", describeNameReject(whyM))
	}
	mcVersion = safeMC
	safeLV, whyL := SafeLoaderComponent(loaderVersion)
	if whyL != nameRejectNone {
		return fmt.Errorf("加载器版本无效: %s", describeNameReject(whyL))
	}
	loaderVersion = safeLV
	customName := fmt.Sprintf("%s %s (%s)", loaderName, loaderVersion, mcVersion)
	if safeName, why := SafeVersionDisplayName(customName); why != nameRejectNone {
		return fmt.Errorf("加载器任务名称无效: %s", describeNameReject(why))
	} else {
		customName = safeName
	}
	// 下载地址来自前端，最终会"下载即运行"第三方安装器：入队时就先把非 HTTPS
	// 链接挡掉，避免恶意 / 被劫持的明文地址进入队列后才在下载阶段暴露。
	// 空地址交给下载阶段统一报错（个别加载器走内置安装器路径时可能不带 URL）。
	if strings.TrimSpace(downloadURL) != "" && !isHTTPSURL(downloadURL) {
		return fmt.Errorf("不支持的加载器下载地址（仅允许 HTTPS）")
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	pending := DownloadItem{
		ID:         fmt.Sprintf("loader-%s-%s", loaderName, loaderVersion),
		URL:        downloadURL,
		CustomName: customName,
		Type:       "loader",
		ItemType:   "loader",
		Status:     "pending",
		Progress:   0,
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

func (a *App) downloadLoaderItem(item *DownloadItem) error {
	if item.URL == "" {
		return fmt.Errorf("下载地址为空")
	}

	if !isHTTPSURL(item.URL) {
		return fmt.Errorf("不安全的下载 URL（非 HTTPS）")
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	// 落盘目标名不再直接取展示名：走 loaderdest 内核，按 URL 路径判定扩展名
	// （忽略 query）、slug 白名单化、追加 UMFS 指纹去碰撞，并断言结果仍严格位于
	// TEMP 内。旧实现 filepath.Base(CustomName) 保留空格 / 括号、文件名可预测，
	// 且 URL 带 ?query 时会漏判 .jar。
	artifactExt := loaderArtifactExt(item.URL)
	destPath, ok := resolveLoaderTempDest(tempDir, item.CustomName, item.URL)
	if !ok {
		return fmt.Errorf("无法在临时目录内构造安全的安装器落盘路径")
	}
	fileName := filepath.Base(destPath)

	a.emitProgress("downloading", fileName, 0, 0)

	if err := a.downloadFile(item.URL, destPath, true); err != nil {
		return fmt.Errorf("下载加载器失败: %v", err)
	}

	if artifactExt == ".jar" {
		javaEntry := a.SearchJava()
		if len(javaEntry) == 0 {
			return fmt.Errorf("下载完成但未找到 Java 来运行安装器，请手动运行: %s", destPath)
		}
		// “下载即运行”的第三方 jar 风险最高：审计目标 jar 必须是 tempDir 内的绝对
		// .jar，阻止 UNC / 穿越 / 目录之外目标，java 可执行同样过绝对/扩展名校验。
		dlAudit := AuditExternalJVM(ExternalJVMPlan{
			JavaExe:      javaEntry[0].Path,
			WorkDir:      tempDir,
			JarAbsPath:   destPath,
			AllowedRoots: []string{tempDir},
		})
		if dlAudit.HasCritical() {
			return fmt.Errorf("下载的安装器启动审计未通过: %s", dlAudit.FirstCriticalCode())
		}
		cmd := exec.Command(javaEntry[0].Path, "-jar", destPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		// 下载下来的第三方 jar 安装器也是独立 JVM，同样不能继承隐式 JVM
		// 参数环境变量，否则下载即运行这条链会被 JAVA_TOOL_OPTIONS 劫持。
		a.applySanitizedJVMEnv(cmd, "DownloadedJarInstaller", nil)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("启动安装器失败: %v", err)
		}
	}

	return nil
}
