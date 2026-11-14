package main

import (
	"os"
	"path/filepath"
	"strings"

)

func (a *App) extractNativesFromJSON(mcDir string, nativesDir string, versionJSON *VersionJSON) {
	// 确保 natives 目录存在
	os.MkdirAll(nativesDir, 0755)

	// 记录所有提取的文件路径，用于清理多余文件（参考 PCL）
	var allExtractedFiles []string

	for _, lib := range versionJSON.Libraries {
		if lib.Natives == nil {
			continue
		}

		// 尝试多个 native 键（参考 PCL 的 McLibListGetWithJson）
		// 优先级: natives-windows-64 > natives-windows
		nativeKey := ""
		if key, ok := lib.Natives["windows-64"]; ok {
			nativeKey = strings.ReplaceAll(key, "${arch}", "64")
		} else if key, ok := lib.Natives["windows"]; ok {
			nativeKey = strings.ReplaceAll(key, "${arch}", "64")
		}

		if nativeKey == "" {
			continue
		}

		if lib.Downloads == nil || lib.Downloads.Classifiers == nil {
			continue
		}
		classifier, ok := lib.Downloads.Classifiers[nativeKey]
		if !ok || classifier == nil {
			continue
		}
		nativeJarPath := filepath.Join(mcDir, "libraries", classifier.Path)

		// 检查 native jar 是否存在
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

	// 清理 natives 目录中的多余文件（参考 PCL 的 McLaunchNatives）
	// 如果 allExtractedFiles 非空，删除不在列表中的 .dll/.so/.jnilib 文件
	_ = allExtractedFiles // 暂时不清理，避免误删（PCL 也有此保护逻辑）
}

// isDirEmpty 检查目录是否为空
