package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func (a *App) downloadFabricLibraries(profileJSON map[string]interface{}, mcDir string) {
	libsDir := filepath.Join(mcDir, "libraries")

	libs, ok := profileJSON["libraries"].([]interface{})
	if !ok {
		fmt.Printf("Fabric profile JSON 中没有 libraries 字段\n")
		return
	}

	downloadedCount := 0
	for _, libRaw := range libs {
		libMap, ok := libRaw.(map[string]interface{})
		if !ok {
			continue
		}

		downloads, ok := libMap["downloads"].(map[string]interface{})
		if !ok {
			continue
		}

		artifact, ok := downloads["artifact"].(map[string]interface{})
		if !ok {
			continue
		}

		url, _ := artifact["url"].(string)
		path, _ := artifact["path"].(string)
		if url == "" || path == "" {
			continue
		}

		// 供应链 RCE 防护（与 Forge 库一致）：profile JSON 不可信，artifact.url 可能被
		// 篡改指向攻击者自己的 https 服务器。先对“原始”主机做白名单校验（在镜像
		// 替换之前），拒绝非白名单主机 / userinfo / 非标端口，避免只校验 https scheme。
		if !isAllowedMavenLibURL(url) {
			fmt.Printf("跳过非信任主机的 Fabric 库 URL: %s\n", url)
			continue
		}

		sha1, _ := artifact["sha1"].(string)

		url = rewriteFabricLibURLToBMCL(url)

		// Zip Slip 防护：库路径走严格 Maven 相对路径白名单
		safePath := SafeMavenRelPath(path)
		if safePath == "" {
			fmt.Printf("跳过不安全的库路径: %s\n", path)
			continue
		}
		destPath := filepath.Join(libsDir, filepath.FromSlash(safePath))

		// 走带官方 sha1 锚点的下载（缺失时退化为侧车 UMFS/SHA512/SHA1 复核），
		// 已存在文件也会复核，杜绝“预置坏 jar + os.Stat 跳过”。
		if err := a.downloadVerifiedFile(url, destPath, strings.TrimSpace(sha1), false); err != nil {
			fmt.Printf("下载 Fabric 库失败 %s: %v\n", path, err)
		} else {
			downloadedCount++
		}
	}

	if downloadedCount > 0 {
		fmt.Printf("Fabric 库文件预下载完成: 成功下载 %d 个\n", downloadedCount)
	}
}
