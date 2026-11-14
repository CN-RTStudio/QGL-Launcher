package main

import (
	"fmt"
)

func formatMaxVer(maxMajor int) string {
	if maxMajor <= 0 {
		return "无上限"
	}
	return fmt.Sprintf("%d", maxMajor)
}
func (a *App) GetJavaInfo(javaPath string) *JavaEntry {
	if javaPath == "" {
		return nil
	}
	return validateJava(javaPath)
}

type JavaDownloadInfo struct {
	MajorVer  int    `json:"majorVer"`  // 主版本号
	Name      string `json:"name"`      // 显示名称
	URL       string `json:"url"`       // 下载链接
	FileName  string `json:"fileName"`  // 保存的文件名
	IsMSI     bool   `json:"isMSI"`     // 是否为 MSI 安装包
	IsZip     bool   `json:"isZip"`     // 是否为 ZIP 压缩包
	IsWebPage bool   `json:"isWebPage"` // 是否为网页链接（无法直接下载）
}

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
