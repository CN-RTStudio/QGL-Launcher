package main

import (
	"encoding/json"
	"fmt"
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
func (a *App) getSecureJarHandlerVersion(versionID string, versionJSON *VersionJSON) string {
	for _, lib := range versionJSON.Libraries {
		if strings.Contains(lib.Name, "securejarhandler") {
			// lib.Name 格式: "cpw.mods:securejarhandler:0.9.45"
			parts := strings.Split(lib.Name, ":")
			if len(parts) >= 3 {
				return parts[2]
			}
		}
	}
	return ""
}

// parseMCVersion 解析 MC 版本号，返回 (major, minor, patch)
func parseMCVersion(versionID string) (int, int, int) {
	// 去除可能的快照后缀
	versionID = strings.Split(versionID, "-")[0]
	versionID = strings.Split(versionID, " ")[0]

	parts := strings.Split(versionID, ".")
	major, _ := strconv.Atoi(parts[0])
	minor := 0
	patch := 0
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	return major, minor, patch
}

// SelectJavaForVersion 为指定 MC 版本选择合适的 Java
func (a *App) SelectJavaForVersion(versionID string) (*JavaEntry, error) {
	req := a.GetJavaRequirement(versionID)

	// 1. 便携版模式：优先使用 QGL\pe\java\bin\java.exe
	config, _ := a.GetGlobalConfig()
	if config != nil && config.PortableMode {
		portableJava := a.GetPortableJavaInfo()
		if portableJava != nil {
			if isJavaCompatible(portableJava, req) {
				return portableJava, nil
			}
			// 便携版 Java 不兼容，继续搜索其他 Java
		}
	}

	// 2. 检查用户手动设置的 Java
	if config != nil && config.JavaPath != "" {
		javaEntry := validateJava(config.JavaPath)
		if javaEntry != nil {
			if isJavaCompatible(javaEntry, req) {
				return javaEntry, nil
			}
			// 手动设置的 Java 不兼容，返回提示
			displayMin := req.MinMajor
			if displayMin <= 0 {
				displayMin = 8
			}
			return nil, fmt.Errorf("手动设置的 Java %s (Java %d) 不适用于 MC %s (需要 Java %d-%s)，请在设置中更换 Java",
				javaEntry.Version, javaEntry.MajorVer, versionID, displayMin, formatMaxVer(req.MaxMajor))
		}
	}

	// 3. 搜索系统中所有 Java
	javaList := a.SearchJava()

	// 3. 过滤出兼容的 Java
	var compatible []JavaEntry
	for _, j := range javaList {
		if isJavaCompatible(&j, req) {
			compatible = append(compatible, j)
		}
	}

	if len(compatible) > 0 {
		return &compatible[0], nil
	}

	// 4. 没有找到兼容的 Java
	displayMin := req.MinMajor
	if displayMin <= 0 {
		displayMin = 8
	}
	if len(javaList) == 0 {
		return nil, fmt.Errorf("未找到任何已安装的 Java，请安装 Java %d 或更高版本", displayMin)
	}

	// 有 Java 但不兼容
	best := javaList[0]
	return nil, fmt.Errorf("未找到适用于 MC %s 的 Java (需要 Java %d-%s)，当前最接近的 Java 为 %s (Java %d)，请安装合适的 Java 版本",
		versionID, displayMin, formatMaxVer(req.MaxMajor), best.Version, best.MajorVer)
}

// isJavaCompatible 检查 Java 是否满足版本需求
func isJavaCompatible(java *JavaEntry, req JavaVersionReq) bool {
	if req.MinMajor > 0 && java.MajorVer < req.MinMajor {
		return false
	}
	if req.MaxMajor > 0 && java.MajorVer > req.MaxMajor {
		return false
	}
	return true
}

// formatMaxVer 格式化最大版本号
