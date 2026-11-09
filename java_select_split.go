package main

import (
	"strings"
)

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
