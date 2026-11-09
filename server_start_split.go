package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// resolveServerJarDownload 解析指定版本服务端 JAR 的最终下载地址与官方 SHA1。
// 地址已强制 https，并把 Mojang 主机替换为 BMCLAPI 镜像；SHA1 仍取官方清单，
// 镜像换源不改变信任锚。
func (a *App) resolveServerJarDownload(version string) (string, string, error) {
	manifest, err := a.GetVersionManifest()
	if err != nil {
		return "", "", fmt.Errorf("获取版本清单失败: %v", err)
	}
	var versionURL string
	for _, v := range manifest {
		if v.ID == version {
			versionURL = v.URL
			break
		}
	}
	if versionURL == "" {
		return "", "", fmt.Errorf("找不到版本 %s", version)
	}
	if !strings.HasPrefix(versionURL, "https://") {
		return "", "", fmt.Errorf("版本清单 URL 必须使用 HTTPS")
	}
	versionURL = rewriteMetaIndexURLToBMCL(versionURL)
	if !urlOnTrustedHost(versionURL, allowedVersionMetaHosts) {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityCritical, auditActionBlocked,
			"server-version-manifest", "版本清单地址不在可信元数据主机白名单内")
		return "", "", fmt.Errorf("版本清单地址不在可信元数据主机白名单内")
	}

	// 版本 JSON 很小，限制 8MB 足够
	resp, err := safeGet(httpClient, versionURL, 8<<20)
	if err != nil {
		return "", "", fmt.Errorf("下载版本 JSON 失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("下载版本 JSON 失败 (HTTP %d)", resp.StatusCode)
	}

	// safeGet 已用 MaxBytesReader 限制体积，但读体中途断连仍会留下截断字节，
	// 必须显式判错：否则会把半个 JSON 交给 Unmarshal，报成"解析失败"而掩盖真实
	// 的网络中断，也让调用方无法据此区分镜像故障与数据损坏。
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", "", fmt.Errorf("读取版本 JSON 响应体失败: %v", readErr)
	}
	var versionJSON map[string]interface{}
	if err := json.Unmarshal(body, &versionJSON); err != nil {
		return "", "", fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	downloads, ok := versionJSON["downloads"].(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("版本 JSON 中没有 downloads 字段")
	}
	server, ok := downloads["server"].(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("Mojang 没有为 %s 提供官方服务端下载", version)
	}
	jarURL, _ := server["url"].(string)
	if jarURL == "" {
		return "", "", fmt.Errorf("无法获取服务端下载地址")
	}
	if !strings.HasPrefix(jarURL, "https://") {
		return "", "", fmt.Errorf("服务端下载地址必须使用 HTTPS")
	}
	expectedHash, _ := server["sha1"].(string)

	jarURL = rewriteMappedDataURLToBMCL(jarURL)
	// 仅校验 https 前缀不足以防止恶意 / 被篡改的版本清单把 downloads.server.url
	// 指向任意主机：最终必须落在可信的 Mojang / BMCLAPI 主机白名单上（与依赖库同一
	// 套 isAllowedMavenLibURL 判定，强制 https、无 userinfo、443、主机精确命中）。
	if !isAllowedMavenLibURL(jarURL) {
		return "", "", fmt.Errorf("服务端下载地址不在可信主机白名单内")
	}
	return jarURL, expectedHash, nil
}

// StartServer 启动服务器
