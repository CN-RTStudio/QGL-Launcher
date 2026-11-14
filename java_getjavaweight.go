package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

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
func (a *App) GetJavaRequirement(versionID string) JavaVersionReq {
	req := JavaVersionReq{
		MinMajor: 0,
		MaxMajor: 0, // 0 表示无上限
	}

	// 读取版本 JSON 获取发布时间
	mcDir := a.getMinecraftDir()
	jsonPath := filepath.Join(mcDir, "versions", versionID, versionID+".json")
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		// 无法读取，使用默认需求
		return req
	}

	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return req
	}

	// 解析发布时间
	releaseTime := versionJSON.ReleaseTime
	releaseYear := 0
	if len(releaseTime) >= 4 {
		releaseYear, _ = strconv.Atoi(releaseTime[:4])
	}
	releaseMonth := 0
	if len(releaseTime) >= 7 {
		releaseMonth, _ = strconv.Atoi(releaseTime[5:7])
	}

	// 解析 MC 版本号
	mcMajor, mcMinor, mcPatch := parseMCVersion(versionID)

	// 根据版本号和发布时间确定 Java 需求（参考PCL的McLaunchJava）
	_ = mcPatch

	// MC 1.20.5+ (24w14a+) -> Java 21+
	if mcMajor > 1 || (mcMajor == 1 && mcMinor >= 21) || (mcMajor == 1 && mcMinor == 20 && mcPatch >= 5) {
		req.MinMajor = 21
	} else if mcMajor > 1 || (mcMajor == 1 && mcMinor >= 18) {
		// MC 1.18+ -> Java 17+
		req.MinMajor = 17
	} else if mcMajor > 1 || (mcMajor == 1 && mcMinor >= 17) {
		// MC 1.17+ -> Java 16+
		req.MinMajor = 16
	} else if releaseYear >= 2017 {
		// MC 1.12+ -> Java 8+
		req.MinMajor = 8
	}

	// MC 1.16.5 及更早版本：Java 17+ 不兼容（内部 API 变更导致崩溃）
	if mcMajor == 1 && mcMinor <= 16 {
		req.MaxMajor = 16
	}
	// MC 1.5.2 及更早 -> Java 最高 12（更严格的限制，覆盖上面的 16）
	if releaseYear < 2013 || (releaseYear == 2013 && releaseMonth <= 5) {
		req.MaxMajor = 12
	}

	// ===== 低版本 Forge 与高版本 Java 不兼容检测 =====
	// 参考 PCL：CrashReason.低版本Forge与高版本Java不兼容
	// securejarhandler 0.9.x 在 Java 17+ 中会崩溃（NoSuchMethodError: ManifestEntryVerifier）
	// securejarhandler 2.x 修复了此问题
	// Forge 1.17.x 早期版本（< 37.0.26）使用 securejarhandler 0.9.45，与 Java 17+ 不兼容
	// Forge 1.18+ 使用 securejarhandler 2.x，与 Java 17+ 兼容
	if mcMajor == 1 && mcMinor == 17 && req.MaxMajor == 0 {
		// 检查是否是 Forge 版本
		versionIDLower := strings.ToLower(versionID)
		if strings.Contains(versionIDLower, "forge") {
			// 检查 securejarhandler 版本
			sjhVersion := a.getSecureJarHandlerVersion(versionID, &versionJSON)
			if sjhVersion != "" && strings.HasPrefix(sjhVersion, "0.") {
				// securejarhandler 0.x 与 Java 17+ 不兼容，限制最高 Java 16
				req.MaxMajor = 16
			}
		}
	}

	// 检查版本 JSON 中的 java_version 字段（新版 MC 可能包含）
	// 这在 version.json 的根级别或 jar 内的 version.json 中
	// 暂时不从 jar 中读取，只检查外部 JSON

	return req
}

// getSecureJarHandlerVersion 获取版本 JSON 中 securejarhandler 的版本号
// 用于检测低版本 Forge 与高版本 Java 的兼容性
