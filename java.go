package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
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
