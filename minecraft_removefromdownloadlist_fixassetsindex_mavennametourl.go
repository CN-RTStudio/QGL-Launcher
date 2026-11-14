package main

import (
	"fmt"
	"strings"

)

func mavenNameToURL(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}

	group := strings.ReplaceAll(parts[0], ".", "/")
	artifact := parts[1]
	version := parts[2]
	classifier := ""
	if len(parts) >= 4 {
		classifier = "-" + parts[3]
	}

	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)
	return fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s", group, artifact, version, fileName)
}

// extractNatives 从 jar 中提取 dll/jnilib/so 文件到目标目录
// 返回提取的文件数量
// 增强：处理损坏的 jar 文件、清理多余文件（参考 PCL 的 McLaunchNatives）
