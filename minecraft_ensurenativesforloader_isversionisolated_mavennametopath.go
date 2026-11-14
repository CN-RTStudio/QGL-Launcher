package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

)

func mavenNameToPath(name string, libsDir string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}

	group := strings.ReplaceAll(parts[0], ".", string(os.PathSeparator))
	artifact := parts[1]
	version := parts[2]
	classifier := ""
	if len(parts) >= 4 {
		classifier = "-" + parts[3]
	}

	// 文件名: artifact-version(-classifier).jar
	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)

	// 完整路径: libsDir/group/artifact/version/fileName
	return filepath.Join(libsDir, group, artifact, version, fileName)
}

// resolveVersionJSON 解析版本 JSON，处理 inheritsFrom 继承关系
// Forge/Fabric/NeoForge/OptiFine 版本都通过 inheritsFrom 引用原版版本
// 需要合并父版本的 libraries、downloads、assetIndex 等信息
