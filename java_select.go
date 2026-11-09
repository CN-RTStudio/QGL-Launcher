package main

import (
	"path/filepath"
	"strconv"
	"strings"
)

func (a *App) GetJavaRequirement(versionID string) JavaVersionReq {
	req := JavaVersionReq{
		MinMajor: 0,
		MaxMajor: 0, // 0 表示无上限
	}
	// 安全：验证 versionID 不含路径遍历
	if err := sanitizePathComponent(versionID); err != nil {
		return req
	}
	// 读取版本 JSON 获取发布时间
	mcDir := a.GetMinecraftDir()
	jsonPath := filepath.Join(mcDir, "versions", versionID, versionID+".json")
	var versionJSON VersionJSON
	if err := readLocalJSONBounded(jsonPath, &versionJSON, 0, "版本 JSON"); err != nil {
		// 无法读取/解析，使用默认需求
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
	} else if mcMajor == 1 && mcMinor >= 18 {
		// MC 1.18+ -> Java 17+（走到 else 时 mcMajor>1 已被上一支覆盖）
		req.MinMajor = 17
	} else if mcMajor == 1 && mcMinor >= 17 {
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
// r34：实现改为复用 semverguard 的严格解析内核。旧实现用 strconv.Atoi 逐段转换且
// 完全忽略错误，"1.abc" 会得到 major=1/minor=0、"1.20.x" 的 patch 静默变 0，负数与
// 溢出段也不被识别，导致“按版本挑 Java”落到错误默认值。现在先剥离 forge/fabric 等
// 加载器后缀，再要求上游版本核心严格可解析；release / prerelease 返回真实主.次.
// 修订，快照（24w14a）与任何畸形串统一返回 0,0,0（与历史“无法解析”默认值一致）。
func parseMCVersion(versionID string) (int, int, int) {
	core := stripLoaderSuffix(versionID)
	parsed, ok := ParseMinecraftVersion(core)
	if !ok {
		return 0, 0, 0
	}
	if parsed.Kind != mcVersionRelease && parsed.Kind != mcVersionPrerelease {
		return 0, 0, 0
	}
	return parsed.Major, parsed.Minor, parsed.Patch
}
