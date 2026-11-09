package main

import (
	"fmt"
)

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
