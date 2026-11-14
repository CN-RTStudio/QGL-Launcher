package main

import (
	"regexp"
)

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
