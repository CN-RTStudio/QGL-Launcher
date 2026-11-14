package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// JavaEntry 表示一个已安装的 Java 运行时
type JavaEntry struct {
	Path       string `json:"path"`       // javaw.exe 完整路径
	Version    string `json:"version"`    // 版本号字符串，如 "1.8.0_321"
	MajorVer   int    `json:"majorVer"`   // 主版本号，如 8, 17, 21
	Is64Bit    bool   `json:"is64Bit"`    // 是否64位
	IsJDK      bool   `json:"isJDK"`      // 是否JDK
}

// JavaVersionReq 表示 MC 版本对 Java 的版本需求
type JavaVersionReq struct {
	MinMajor int // 最低主版本号
	MaxMajor int // 最高主版本号（0表示无上限）
}

// SearchJava 搜索系统中所有已安装的 Java
func (a *App) SearchJava() []JavaEntry {
	var results []JavaEntry
	seen := make(map[string]bool)

	// 1. 搜索常见安装路径
	commonPaths := []string{
		"C:\\Program Files\\Java",
		"C:\\Program Files (x86)\\Java",
		"C:\\Program Files\\Eclipse Adoptium",
		"C:\\Program Files (x86)\\Eclipse Adoptium",
		"C:\\Program Files\\Microsoft",
		"C:\\Program Files\\AdoptOpenJDK",
		"C:\\Program Files\\Zulu",
		"C:\\Program Files\\BellSoft",
		"C:\\Program Files\\Amazon Corretto",
		"C:\\Program Files\\Semeru",
	}

	for _, baseDir := range commonPaths {
		entries, err := os.ReadDir(baseDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			javawPath := filepath.Join(baseDir, entry.Name(), "bin", "javaw.exe")
			if _, err := os.Stat(javawPath); err == nil {
				if !seen[javawPath] {
					seen[javawPath] = true
					javaEntry := validateJava(javawPath)
					if javaEntry != nil {
						results = append(results, *javaEntry)
					}
				}
			}
		}
	}

	// 2. JAVA_HOME 环境变量
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		javawPath := filepath.Join(javaHome, "bin", "javaw.exe")
		if _, err := os.Stat(javawPath); err == nil && !seen[javawPath] {
			seen[javawPath] = true
			javaEntry := validateJava(javawPath)
			if javaEntry != nil {
				results = append(results, *javaEntry)
			}
		}
	}

	// 3. PATH 环境变量
	pathEnv := os.Getenv("PATH")
	if pathEnv != "" {
		paths := strings.Split(pathEnv, ";")
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			javawPath := filepath.Join(p, "javaw.exe")
			if _, err := os.Stat(javawPath); err == nil && !seen[javawPath] {
				// 排除 system32 中的重定向
				if strings.Contains(strings.ToLower(javawPath), "system32") {
					continue
				}
				seen[javawPath] = true
				javaEntry := validateJava(javawPath)
				if javaEntry != nil {
					results = append(results, *javaEntry)
				}
			}
		}
	}

	// 4. 搜索 QGL 自身目录
	exePath, _ := os.Executable()
	appDir := filepath.Dir(exePath)
	searchDirForJava(appDir, &results, seen, 3)

	// 5. 搜索 .minecraft 目录
	mcDir := a.getMinecraftDir()
	searchDirForJava(mcDir, &results, seen, 3)

	// 6. 搜索 AppData 下的 Java
	appData := os.Getenv("APPDATA")
	if appData != "" {
		searchDirForJava(appData, &results, seen, 2)
	}
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData != "" {
		searchDirForJava(localAppData, &results, seen, 2)
	}

	// 7. 搜索所有本地磁盘驱动器（参考PCL的磁盘全盘遍历）
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		drivePath := string(drive) + ":\\"
		if _, err := os.Stat(drivePath); err != nil {
			continue // 驱动器不存在
		}
		// 搜索驱动器根目录下的 Java 相关文件夹
		searchDriveForJava(drivePath, &results, seen)
	}

	// 排序：优先64位，然后按权重排序
	sort.Slice(results, func(i, j int) bool {
		// 64位优先
		if results[i].Is64Bit != results[j].Is64Bit {
			return results[i].Is64Bit
		}
		// 按权重排序（参考PCL的JavaSorter权重数组）
		weightI := getJavaWeight(results[i].MajorVer)
		weightJ := getJavaWeight(results[j].MajorVer)
		if weightI != weightJ {
			return weightI > weightJ
		}
		return results[i].MajorVer > results[j].MajorVer
	})

	return results
}

// searchDriveForJava 搜索磁盘驱动器上的 Java（参考PCL的磁盘遍历逻辑）
// 只搜索根目录下的 Java 相关文件夹，避免全盘递归太慢
func searchDriveForJava(drivePath string, results *[]JavaEntry, seen map[string]bool) {
	entries, err := os.ReadDir(drivePath)
	if err != nil {
		return
	}

	// 需要进入搜索的根目录关键字（参考PCL的JavaSearchFolder关键字列表）
	rootKeywords := []string{
		"java", "jdk", "jre", "program", "software", "soft", "app",
		"develop", "dev", "tools", "runtime", "env", "游戏", "game",
		"mc", "minecraft", "launch", "启动", "运行", "应用",
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		lowerName := strings.ToLower(name)

		// 直接检查该目录下是否有 bin/javaw.exe
		javawPath := filepath.Join(drivePath, name, "bin", "javaw.exe")
		if _, err := os.Stat(javawPath); err == nil && !seen[javawPath] {
			seen[javawPath] = true
			javaEntry := validateJava(javawPath)
			if javaEntry != nil {
				*results = append(*results, *javaEntry)
			}
		}

		// 判断是否需要进入该目录搜索
		shouldEnter := false
		for _, kw := range rootKeywords {
			if strings.Contains(lowerName, kw) {
				shouldEnter = true
				break
			}
		}

		if shouldEnter {
			searchDirForJava(filepath.Join(drivePath, name), results, seen, 4)
		}
	}
}

// searchDirForJava 在指定目录下搜索 Java（参考PCL的JavaSearchFolder关键字过滤）
func searchDirForJava(dir string, results *[]JavaEntry, seen map[string]bool, maxDepth int) {
	if maxDepth <= 0 {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	// 关键字列表（参考PCL）
	keywords := []string{
		"java", "jdk", "jre", "runtime", "env", "run", "soft",
		"corretto", "adoptium", "zulu", "semeru", "microsoft",
		"eclipse", "oracle", "hotspot", "openjdk", "bellsoft",
		"program", "game", "mc", "minecraft", "version",
		"x64", "x86", "bin", "users",
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		lowerName := strings.ToLower(name)

		// 检查 bin 目录下是否有 javaw.exe
		javawPath := filepath.Join(dir, name, "bin", "javaw.exe")
		if _, err := os.Stat(javawPath); err == nil && !seen[javawPath] {
			seen[javawPath] = true
			javaEntry := validateJava(javawPath)
			if javaEntry != nil {
				*results = append(*results, *javaEntry)
			}
		}

		// 决定是否进入子目录
		shouldEnter := false
		// 数字开头的目录（版本号）
		if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
			shouldEnter = true
		}
		// bin 目录无条件进入
		if lowerName == "bin" {
			shouldEnter = true
		}
		// users 目录无条件进入
		if lowerName == "users" {
			shouldEnter = true
		}
		// 关键字匹配
		if !shouldEnter {
			for _, kw := range keywords {
				if strings.Contains(lowerName, kw) {
					shouldEnter = true
					break
				}
			}
		}

		if shouldEnter {
			searchDirForJava(filepath.Join(dir, name), results, seen, maxDepth-1)
		}
	}
}

// validateJava 验证 Java 路径并获取版本信息（参考PCL的JavaEntry.Check）
func validateJava(javawPath string) *JavaEntry {
	// 检查 javaw.exe 是否存在
	if _, err := os.Stat(javawPath); err != nil {
		return nil
	}

	// 检查 java.exe 是否存在（同目录下）
	dir := filepath.Dir(javawPath)
	javaExePath := filepath.Join(dir, "java.exe")
	if _, err := os.Stat(javaExePath); err != nil {
		return nil
	}

	// 判断是否为 JDK（检查 javac.exe）
	javacPath := filepath.Join(dir, "javac.exe")
	isJDK := false
	if _, err := os.Stat(javacPath); err == nil {
		isJDK = true
	}

	// 运行 java -version 获取版本信息
	cmd := exec.Command(javaExePath, "-version")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 某些 Java 即使成功也会返回非零退出码
		// 尝试解析输出
	}

	outputStr := string(output)

	// 解析版本号（参考PCL的正则匹配逻辑）
	version, majorVer := parseJavaVersion(outputStr)
	if majorVer <= 0 {
		return nil
	}

	// 检测是否为64位
	is64Bit := strings.Contains(outputStr, "64-Bit") || strings.Contains(outputStr, "64-bit")

	return &JavaEntry{
		Path:     javawPath,
		Version:  version,
		MajorVer: majorVer,
		Is64Bit:  is64Bit,
		IsJDK:    isJDK,
	}
}

// parseJavaVersion 从 java -version 输出中解析版本号
func parseJavaVersion(output string) (string, int) {
	// 匹配 "1.8.0_321" 或 "17.0.3" 或 "21.0.1" 等格式
	re1 := regexp.MustCompile(`version "([^"]+)"`)
	matches := re1.FindStringSubmatch(output)
	if len(matches) >= 2 {
		rawVersion := matches[1]
		return normalizeJavaVersion(rawVersion)
	}

	// 匹配 openjdk 格式
	re2 := regexp.MustCompile(`openjdk (\d[\d._]*)`)
	matches = re2.FindStringSubmatch(output)
	if len(matches) >= 2 {
		rawVersion := matches[1]
		return normalizeJavaVersion(rawVersion)
	}

	return "", 0
}

// normalizeJavaVersion 标准化 Java 版本号并提取主版本号
func normalizeJavaVersion(raw string) (string, int) {
	// 将 _ 替换为 .
	raw = strings.ReplaceAll(raw, "_", ".")
	// 取 - 前的部分
	if idx := strings.Index(raw, "-"); idx > 0 {
		raw = raw[:idx]
	}

	// 解析版本号段
	parts := strings.Split(raw, ".")
	majorVer := 0

	if len(parts) >= 1 {
		// 如果以 "1." 开头（旧版本格式，如 1.8.0）
		if parts[0] == "1" && len(parts) >= 2 {
			// 主版本号是第二段
			majorVer, _ = strconv.Atoi(parts[1])
		} else {
			// 新版本格式，主版本号是第一段（如 17, 21）
			majorVer, _ = strconv.Atoi(parts[0])
		}
	}

	if majorVer <= 0 || majorVer >= 100 {
		return "", 0
	}

	return raw, majorVer
}

// getJavaWeight 获取 Java 版本的排序权重（参考PCL的JavaSorter权重数组）
func getJavaWeight(majorVer int) int {
	// PCL 的权重数组（索引 = Java 大版本号）
	weights := map[int]int{
		7:  14,
		8:  30,
		9:  10,
		10: 12,
		11: 15,
		12: 13,
		13: 9,
		14: 8,
		15: 7,
		16: 11,
		17: 31,
		18: 29,
		19: 16,
		20: 17,
		21: 28,
		22: 27,
		23: 26,
		24: 25,
		25: 24,
		26: 23,
		27: 22,
		28: 21,
		29: 20,
		30: 19,
	}
	if w, ok := weights[majorVer]; ok {
		return w
	}
	if majorVer > 30 {
		return 18
	}
	return 0
}

// GetJavaRequirement 根据 MC 版本获取 Java 版本需求（参考PCL的McLaunchJava）
func (a *App) GetJavaRequirement(versionID string) JavaVersionReq {
	req := JavaVersionReq{
		MinMajor: 0,
		MaxMajor: 0, // 0 表示无上限
	}

	// 读取版本 JSON 获取发布时间
	mcDir := a.getMinecraftDir()
	jsonPath := filepath.Join(mcDir, "versions", versionID, versionID+".json")
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		// 无法读取，使用默认需求
		return req
	}

	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return req
	}

	// 解析发布时间
	releaseTime := versionJSON.ReleaseTime
	releaseYear := 0
	if len(releaseTime) >= 4 {
		releaseYear, _ = strconv.Atoi(releaseTime[:4])
	}
	releaseMonth := 0
	if len(releaseTime) >= 7 {
		releaseMonth, _ = strconv.Atoi(releaseTime[5:7])
	}

	// 解析 MC 版本号
	mcMajor, mcMinor, mcPatch := parseMCVersion(versionID)

	// 根据版本号和发布时间确定 Java 需求（参考PCL的McLaunchJava）
	_ = mcPatch

	// MC 1.20.5+ (24w14a+) -> Java 21+
	if mcMajor > 1 || (mcMajor == 1 && mcMinor >= 21) || (mcMajor == 1 && mcMinor == 20 && mcPatch >= 5) {
		req.MinMajor = 21
	} else if mcMajor > 1 || (mcMajor == 1 && mcMinor >= 18) {
		// MC 1.18+ -> Java 17+
		req.MinMajor = 17
	} else if mcMajor > 1 || (mcMajor == 1 && mcMinor >= 17) {
		// MC 1.17+ -> Java 16+
		req.MinMajor = 16
	} else if releaseYear >= 2017 {
		// MC 1.12+ -> Java 8+
		req.MinMajor = 8
	}

	// MC 1.16.5 及更早版本：Java 17+ 不兼容（内部 API 变更导致崩溃）
	if mcMajor == 1 && mcMinor <= 16 {
		req.MaxMajor = 16
	}
	// MC 1.5.2 及更早 -> Java 最高 12（更严格的限制，覆盖上面的 16）
	if releaseYear < 2013 || (releaseYear == 2013 && releaseMonth <= 5) {
		req.MaxMajor = 12
	}

	// ===== 低版本 Forge 与高版本 Java 不兼容检测 =====
	// 参考 PCL：CrashReason.低版本Forge与高版本Java不兼容
	// securejarhandler 0.9.x 在 Java 17+ 中会崩溃（NoSuchMethodError: ManifestEntryVerifier）
	// securejarhandler 2.x 修复了此问题
	// Forge 1.17.x 早期版本（< 37.0.26）使用 securejarhandler 0.9.45，与 Java 17+ 不兼容
	// Forge 1.18+ 使用 securejarhandler 2.x，与 Java 17+ 兼容
	if mcMajor == 1 && mcMinor == 17 && req.MaxMajor == 0 {
		// 检查是否是 Forge 版本
		versionIDLower := strings.ToLower(versionID)
		if strings.Contains(versionIDLower, "forge") {
			// 检查 securejarhandler 版本
			sjhVersion := a.getSecureJarHandlerVersion(versionID, &versionJSON)
			if sjhVersion != "" && strings.HasPrefix(sjhVersion, "0.") {
				// securejarhandler 0.x 与 Java 17+ 不兼容，限制最高 Java 16
				req.MaxMajor = 16
			}
		}
	}

	// 检查版本 JSON 中的 java_version 字段（新版 MC 可能包含）
	// 这在 version.json 的根级别或 jar 内的 version.json 中
	// 暂时不从 jar 中读取，只检查外部 JSON

	return req
}

// getSecureJarHandlerVersion 获取版本 JSON 中 securejarhandler 的版本号
// 用于检测低版本 Forge 与高版本 Java 的兼容性
func (a *App) getSecureJarHandlerVersion(versionID string, versionJSON *VersionJSON) string {
	for _, lib := range versionJSON.Libraries {
		if strings.Contains(lib.Name, "securejarhandler") {
			// lib.Name 格式: "cpw.mods:securejarhandler:0.9.45"
			parts := strings.Split(lib.Name, ":")
			if len(parts) >= 3 {
				return parts[2]
			}
		}
	}
	return ""
}

// parseMCVersion 解析 MC 版本号，返回 (major, minor, patch)
func parseMCVersion(versionID string) (int, int, int) {
	// 去除可能的快照后缀
	versionID = strings.Split(versionID, "-")[0]
	versionID = strings.Split(versionID, " ")[0]

	parts := strings.Split(versionID, ".")
	major, _ := strconv.Atoi(parts[0])
	minor := 0
	patch := 0
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	return major, minor, patch
}

// SelectJavaForVersion 为指定 MC 版本选择合适的 Java
func (a *App) SelectJavaForVersion(versionID string) (*JavaEntry, error) {
	req := a.GetJavaRequirement(versionID)

	// 1. 便携版模式：优先使用 QGL\pe\java\bin\java.exe
	config, _ := a.GetGlobalConfig()
	if config != nil && config.PortableMode {
		portableJava := a.GetPortableJavaInfo()
		if portableJava != nil {
			if isJavaCompatible(portableJava, req) {
				return portableJava, nil
			}
			// 便携版 Java 不兼容，继续搜索其他 Java
		}
	}

	// 2. 检查用户手动设置的 Java
	if config != nil && config.JavaPath != "" {
		javaEntry := validateJava(config.JavaPath)
		if javaEntry != nil {
			if isJavaCompatible(javaEntry, req) {
				return javaEntry, nil
			}
			// 手动设置的 Java 不兼容，返回提示
			displayMin := req.MinMajor
			if displayMin <= 0 {
				displayMin = 8
			}
			return nil, fmt.Errorf("手动设置的 Java %s (Java %d) 不适用于 MC %s (需要 Java %d-%s)，请在设置中更换 Java",
				javaEntry.Version, javaEntry.MajorVer, versionID, displayMin, formatMaxVer(req.MaxMajor))
		}
	}

	// 3. 搜索系统中所有 Java
	javaList := a.SearchJava()

	// 3. 过滤出兼容的 Java
	var compatible []JavaEntry
	for _, j := range javaList {
		if isJavaCompatible(&j, req) {
			compatible = append(compatible, j)
		}
	}

	if len(compatible) > 0 {
		return &compatible[0], nil
	}

	// 4. 没有找到兼容的 Java
	displayMin := req.MinMajor
	if displayMin <= 0 {
		displayMin = 8
	}
	if len(javaList) == 0 {
		return nil, fmt.Errorf("未找到任何已安装的 Java，请安装 Java %d 或更高版本", displayMin)
	}

	// 有 Java 但不兼容
	best := javaList[0]
	return nil, fmt.Errorf("未找到适用于 MC %s 的 Java (需要 Java %d-%s)，当前最接近的 Java 为 %s (Java %d)，请安装合适的 Java 版本",
		versionID, displayMin, formatMaxVer(req.MaxMajor), best.Version, best.MajorVer)
}

// isJavaCompatible 检查 Java 是否满足版本需求
func isJavaCompatible(java *JavaEntry, req JavaVersionReq) bool {
	if req.MinMajor > 0 && java.MajorVer < req.MinMajor {
		return false
	}
	if req.MaxMajor > 0 && java.MajorVer > req.MaxMajor {
		return false
	}
	return true
}

// formatMaxVer 格式化最大版本号
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
		destPath, safeErr := safeRelPath(baseDir, relPath)
		if safeErr != nil {
			continue
		}
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
