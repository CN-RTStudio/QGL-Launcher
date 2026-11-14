package main

import (
	"strings"

)

func libGroupArtifact(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}
	return name
}

// mavenNameToPath 从 Maven 坐标推算库文件路径（参考 PCL 的 McLibGet）
// Maven 坐标格式: group:artifact:version 或 group:artifact:version:classifier
// 路径格式: group/artifact/version/artifact-version(-classifier).jar
