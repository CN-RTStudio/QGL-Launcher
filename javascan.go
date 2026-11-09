package main

import (
	"os"
	"path/filepath"
	"strings"
)

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
			// 不跟随 junction / 符号链接，避免扫到其它卷或陷入联接环。
			if isReparsePointDir(entry) {
				continue
			}
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
			// 不跟随 junction / 符号链接：AppData 下的目录联接可能指向
			// Program Files 或其它卷，真实目录会由对应的固定扫描路径发现。
			if isReparsePointDir(entry) {
				continue
			}
			searchDirForJava(filepath.Join(dir, name), results, seen, maxDepth-1)
		}
	}
}

// maxJavaVersionOutput 限制 `java -version` 的输出体积。
// 正常输出只有几百字节；用户选择的"Java 路径"是前端绑定方法可直接传入的
// 参数，若放任输出不设上限，一个伪造的 java.exe 打印海量内容即可撑爆内存。
