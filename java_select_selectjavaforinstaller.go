package main

import (
	"fmt"
	"strings"
)

func (a *App) selectJavaForInstaller() (*JavaEntry, error) {
	javaList := a.SearchJava()
	// 优先选择 Java 17+（ForgeInstaller 需要）
	for _, j := range javaList {
		if j.MajorVer >= 17 {
			return &j, nil
		}
	}
	// 回退到 Java 8+（某些旧版安装器可能兼容）
	for _, j := range javaList {
		if j.MajorVer >= 8 {
			return &j, nil
		}
	}
	return nil, fmt.Errorf("未找到合适的 Java（需要 Java 17+，最低 Java 8）")
}

// GetRecommendedJavaForVersion 获取推荐安装的 Java 版本号（供前端提示用）
func (a *App) GetRecommendedJavaForVersion(versionID string) int {
	// 安全：验证 versionID 不含路径遍历
	if err := sanitizePathComponent(versionID); err != nil {
		return 8
	}
	req := a.GetJavaRequirement(versionID)
	if req.MinMajor > 0 {
		return req.MinMajor
	}
	// 对于非常老的版本（MinMajor=0），推荐 Java 8（最兼容的版本）
	return 8
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
