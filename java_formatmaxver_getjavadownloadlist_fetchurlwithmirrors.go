package main

import (
	"fmt"
	"io"
	"net/http"
)

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
