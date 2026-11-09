package main

import (
	"regexp"
	"strconv"
	"strings"
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
func getJavaWeight(majorVer int) int {
	// PCL 的权重数组（索引 = Java 大版本号）
	weights := map[int]int{
		7:  14,
		8:  30,
		9:  10,
		10: 12,
		11: 15,
		12: 13,
		13: 9,
		14: 8,
		15: 7,
		16: 11,
		17: 31,
		18: 29,
		19: 16,
		20: 17,
		21: 28,
		22: 27,
		23: 26,
		24: 25,
		25: 24,
		26: 23,
		27: 22,
		28: 21,
		29: 20,
		30: 19,
	}
	if w, ok := weights[majorVer]; ok {
		return w
	}
	if majorVer > 30 {
		return 18
	}
	return 0
}

// GetJavaRequirement 根据 MC 版本获取 Java 版本需求（参考PCL的McLaunchJava）
