package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
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
