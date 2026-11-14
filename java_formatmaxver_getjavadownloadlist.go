package main

import (
	"fmt"
	"io"
	"net/http"
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
func fetchURLWithMirrors(urls []string) ([]byte, error) {
	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		return data, nil
	}
	return nil, lastErr
}

// downloadJavaRuntime 通过 Mojang 官方 java-runtime 清单下载并安装 Java（免安装版，参考 PCL 的 JavaFileList + LoaderDownload）
// 安装位置：<minecraftDir>/runtime/<运行时key>/，QGL 搜索 Java 时会扫描 .minecraft 目录自动发现
