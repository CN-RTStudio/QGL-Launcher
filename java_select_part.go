package main

import "fmt"

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
	// 4. 过滤出兼容的 Java
	var compatible []JavaEntry
	for _, j := range javaList {
		if isJavaCompatible(&j, req) {
			compatible = append(compatible, j)
		}
	}
	if len(compatible) > 0 {
		return &compatible[0], nil
	}
	// 5. 没有找到兼容的 Java
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
func formatMaxVer(maxMajor int) string {
	if maxMajor <= 0 {
		return "无上限"
	}
	return fmt.Sprintf("%d", maxMajor)
}

// GetJavaInfo 获取指定路径的 Java 信息（供前端调用）
func (a *App) GetJavaInfo(javaPath string) *JavaEntry {
	if javaPath == "" {
		return nil
	}
	return validateJava(javaPath)
}

// ===== Java 下载功能 =====

// JavaDownloadInfo Java 下载信息
type JavaDownloadInfo struct {
	MajorVer  int    `json:"majorVer"`  // 主版本号
	Name      string `json:"name"`      // 显示名称
	URL       string `json:"url"`       // 下载链接
	FileName  string `json:"fileName"`  // 保存的文件名
	IsMSI     bool   `json:"isMSI"`     // 是否为 MSI 安装包
	IsZip     bool   `json:"isZip"`     // 是否为 ZIP 压缩包
	IsWebPage bool   `json:"isWebPage"` // 是否为网页链接（无法直接下载）
}

// GetJavaDownloadList 获取 Java 下载列表
// 使用 Adoptium Temurin（开源 GPLv2+CE，无商业许可风险，自动获取最新安全补丁）
func (a *App) GetJavaDownloadList() []JavaDownloadInfo {
	return []JavaDownloadInfo{
		{
			MajorVer: 21,
			Name:     "Java 21 (LTS)",
			URL:      "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse",
			FileName: "OpenJDK21U-jdk_x64_windows_hotspot.zip",
			IsMSI:    false,
			IsZip:    true,
		},
		{
			MajorVer: 17,
			Name:     "Java 17 (LTS)",
			URL:      "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jdk/hotspot/normal/eclipse",
			FileName: "OpenJDK17U-jdk_x64_windows_hotspot.zip",
			IsMSI:    false,
			IsZip:    true,
		},
		{
			MajorVer: 8,
			Name:     "Java 8 (旧版兼容)",
			URL:      "https://api.adoptium.net/v3/binary/latest/8/ga/windows/x64/jre/hotspot/normal/eclipse",
			FileName: "OpenJDK8U-jre_x64_windows_hotspot.zip",
			IsMSI:    false,
			IsZip:    true,
		},
	}
}

// selectJavaForInstaller 选择适合运行加载器安装器的 Java（需要 Java 17+）
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
