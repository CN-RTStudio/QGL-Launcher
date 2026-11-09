package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DownloadAuthlibInjector 下载并强校验 authlib-injector.jar（javaagent，可执行）。
// 已存在的 jar 也必须通过侧车记录的官方 SHA-256 复核，绝不"文件在就直接用"。
func (a *App) DownloadAuthlibInjector() (string, error) {
	qglDir := a.GetQGLDir()
	jarPath := filepath.Join(qglDir, "authlib-injector.jar")
	if err := os.MkdirAll(qglDir, 0700); err != nil {
		return "", fmt.Errorf("创建目录失败: %v", err)
	}

	downloadURL, expectedSHA256, err := fetchAuthlibLatest()
	if err != nil {
		// 拿不到权威哈希时，只有"已有 jar 且侧车自证完整"才可继续离线复用；
		// 但侧车里的期望值同样来自上次官方哈希，此处无新值，保守起见要求网络可用。
		return "", err
	}

	if state := inspectRegularFile(jarPath); state.trustable() {
		if verifyAuthlibJar(jarPath, expectedSHA256) {
			return jarPath, nil
		}
		// 已存在但哈希不符 / 无侧车：可能被篡改或是旧版本，删除后重下。
		os.Remove(jarPath)
		removeAuthlibMeta(jarPath)
	}

	mirrorURL := strings.ReplaceAll(downloadURL,
		"authlib-injector.yushi.moe",
		"bmclapi2.bangbang93.com/mirrors/authlib-injector")
	candidates := []string{downloadURL}
	if isAllowedAuthlibDownloadURL(mirrorURL) && mirrorURL != downloadURL {
		candidates = append(candidates, mirrorURL)
	}
	if err := downloadAuthlibJarFromCandidates(jarPath, candidates, expectedSHA256); err != nil {
		return "", err
	}
	return jarPath, nil
}

// GetAuthlibInjectorPath 获取 authlib-injector.jar 路径（不存在则下载）
func (a *App) GetAuthlibInjectorPath() (string, error) {
	return a.DownloadAuthlibInjector()
}
