package main

import (
	"strings"

)

func (a *App) shouldIncludeLib(lib Library) bool {
	if len(lib.Rules) == 0 {
		return true // 没有 rules，默认包含
	}

	allow := false
	for _, rule := range lib.Rules {
		osMatch := true
		if rule.OS != nil {
			osMatch = rule.OS.Name == "windows"
		}

		if rule.Action == "allow" {
			if osMatch {
				allow = true
			}
		} else if rule.Action == "disallow" {
			if osMatch {
				allow = false
			}
		}
	}

	return allow
}

// libGroupArtifact 从 Maven 坐标中提取 group:artifact（不含版本号）
// 例如 "org.apache.logging.log4j:log4j-core:2.17.1" -> "org.apache.logging.log4j:log4j-core"
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
