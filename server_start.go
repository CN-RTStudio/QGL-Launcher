package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// downloadServerJar 下载并校验服务器 JAR。
//
// 安全要点（服务端 JAR 随后会被 `java -jar` 执行，属于代码执行面）：
//   - 权威 SHA1 必须存在：Mojang 版本 JSON 的 downloads.server.sha1 缺失时，
//     绝不下载/运行来源不可校验的 JAR（旧逻辑在 sha1 缺失时会“裸奔”执行）；
//   - 已存在的 JAR 也要校验：旧逻辑只要文件在就直接复用，本地被替换/损坏、
//     或上次留下半截文件都会被原样执行。这里走与游戏库相同的侧车回退链
//     UMFS -> SHA512 -> 官方 SHA1，命中才复用，否则删除重下；
//   - 新下载落盘先写同目录 .tmp，用官方 SHA1 校验通过后才 rename 成正式 JAR，
//     随后补写 UMFS/SHA512 侧车。
func (a *App) downloadServerJar(version string, targetDir string) error {
	if err := sanitizePathComponent(version); err != nil {
		return fmt.Errorf("无效的版本号: %v", err)
	}
	jarPath := filepath.Join(targetDir, version+"-server.jar")

	jarURL, expectedHash, err := a.resolveServerJarDownload(version)
	if err != nil {
		return err
	}
	// 服务端 JAR 是要被执行的代码，缺少权威 SHA1 时一律拒绝，不能裸奔。
	expectedHash = strings.ToLower(strings.TrimSpace(expectedHash))
	if expectedHash == "" {
		return fmt.Errorf("版本 %s 的官方清单缺少服务端 SHA1，拒绝运行未校验的 JAR", version)
	}

	// 已有 JAR：必须通过侧车回退链 / 官方 SHA1 才允许复用，否则连同侧车一起删除重下。
	if info, statErr := os.Stat(jarPath); statErr == nil && info.Size() > 0 {
		if a.verifyCachedFile(jarPath, expectedHash) {
			return nil
		}
		_ = os.Remove(jarPath)
		removeCachedFileMeta(jarPath)
	}

	dlResp, err := safeGet(httpClient, jarURL, maxServerJarBytes)
	if err != nil {
		return fmt.Errorf("下载服务端 JAR 失败: %v", err)
	}
	defer dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载服务端 JAR 失败 (HTTP %d)", dlResp.StatusCode)
	}

	// 临时文件放在目标同目录，保证最后的 rename 是同卷原子操作；O_EXCL 避免跟随符号链接。
	tempPath := jarPath + ".tmp"
	if _, err := prepareTempPath(tempPath, time.Now(), staleTempMaxAge); err != nil {
		return fmt.Errorf("清理上次下载的临时文件失败: %v", err)
	}
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %v", err)
	}

	hasher := sha1.New()
	tee := io.TeeReader(dlResp.Body, hasher)
	if _, err := io.Copy(file, tee); err != nil {
		file.Close()
		os.Remove(tempPath)
		return fmt.Errorf("写入文件失败: %v", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("关闭临时文件失败: %v", err)
	}

	// 外部协议摘要（Mojang SHA1）保持原算法，是首次下载唯一的权威校验；不通过绝不 rename。
	if actualHash := hex.EncodeToString(hasher.Sum(nil)); actualHash != expectedHash {
		os.Remove(tempPath)
		removeCachedFileMeta(tempPath)
		return fmt.Errorf("服务端 JAR 哈希校验失败")
	}

	if err := os.Rename(tempPath, jarPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("重命名文件失败: %v", err)
	}

	// 官方 SHA1 已通过：补写本地 UMFS/SHA512 侧车，供下次启动快速且更强地校验。
	if err := a.saveCachedFileMeta(jarPath, expectedHash); err != nil {
		a.writeLog("服务端 JAR 侧车元数据写入失败（不影响完整性）: %s: %v", jarPath, err)
	}
	return nil
}

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
