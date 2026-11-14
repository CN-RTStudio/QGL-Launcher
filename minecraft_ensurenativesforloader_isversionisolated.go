package main

import (
	"fmt"
	"os"
	"path/filepath"

)

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
