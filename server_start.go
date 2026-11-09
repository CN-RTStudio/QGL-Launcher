package main

import (
	"crypto/sha1"
	"encoding/hex"
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
	if actualHash := hex.EncodeToString(hasher.Sum(nil)); !equalHexDigest(actualHash, expectedHash) {
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
