package main

import (
)

func (a *App) GetJavaDownloadList() []JavaDownloadInfo {
	return []JavaDownloadInfo{
		{
			MajorVer:  27,
			Name:      "Java 27",
			URL:       "https://www.oracle.com/cn/java/technologies/downloads/#jdk27-windows",
			FileName:  "jdk-27-windows",
			IsMSI:     false,
			IsWebPage: true,
		},
		{
			MajorVer:  21,
			Name:      "Java 21",
			URL:       "https://www.oracle.com/cn/java/technologies/downloads/#java21-windows",
			FileName:  "jdk-21-windows",
			IsMSI:     false,
			IsWebPage: true,
		},
		{
			MajorVer:  17,
			Name:      "Java 17",
			URL:       "https://www.oracle.com/cn/java/technologies/downloads/#java17-windows",
			FileName:  "jdk-17-windows",
			IsMSI:     false,
			IsWebPage: true,
		},
		{
			MajorVer:  8,
			Name:      "Java 8",
			URL:       "https://www.oracle.com/cn/java/technologies/downloads/#java8-windows",
			FileName:  "java8-windows",
			IsMSI:     false,
			IsWebPage: true,
		},
	}
}

// ===== Mojang 官方 Java 运行时下载（参考 PCL 的 JavaFileList）=====

// mojangJavaRuntimeIndexURL Mojang java-runtime 清单索引（BMCLAPI 有镜像，替换域名即可）
const mojangJavaRuntimeIndexURL = "https://piston-meta.mojang.com/v1/products/java-runtime/2ec0cc96c44e5a76b9c8b7c39df7210883d12871/all.json"

// javaRuntimeManifest Mojang java-runtime 清单条目
type javaRuntimeEntry struct {
	Name     string `json:"name"`
	Version  struct {
		Name string `json:"name"`
	} `json:"version"`
	Manifest struct {
		URL string `json:"url"`
	} `json:"manifest"`
}

// javaRuntimeFileEntry runtime manifest 中的文件条目
type javaRuntimeFileEntry struct {
	Type      string `json:"type"`
	Downloads struct {
		Raw *struct {
			URL  string `json:"url"`
			Size int64  `json:"size"`
			SHA1 string `json:"sha1"`
		} `json:"raw"`
	} `json:"downloads"`
}

// fetchURLWithMirrors 依次尝试多个 URL 获取内容（先官方，失败走 BMCLAPI 镜像）
