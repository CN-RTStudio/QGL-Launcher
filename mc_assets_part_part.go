package main

import "path/filepath"

func (a *App) extractNativesFromJSON(mcDir string, nativesDir string, versionJSON *VersionJSON) {
	// 解压根目录统一收权到 0700（历史上若存在 0755 的 natives 目录会被原样沿用）。
	_ = ensurePrivateDir(nativesDir)
	for _, lib := range versionJSON.Libraries {
		if lib.Natives == nil {
			continue
		}
		// 与下载阶段使用同一套“按真实架构选 Windows natives 键 + ${arch} 替换”
		// 的规则，避免下载和解压挑到不同分类器（旧实现这里只看 windows-64/windows）。
		winEnv := ruleEnv{osName: "windows", osArch: currentRuleEnv().osArch}
		nativeKey, hasNative := resolveWindowsNativeKey(lib.Natives, winEnv)
		if !hasNative {
			continue
		}
		if lib.Downloads == nil || lib.Downloads.Classifiers == nil {
			continue
		}
		classifier, ok := lib.Downloads.Classifiers[nativeKey]
		if !ok || classifier == nil {
			continue
		}
		// 与下载阶段一致，这里必须再次校验 classifier.Path：版本 JSON 来自镜像
		// 站（不可信），而本函数也会被非 DownloadVersion 的其它启动流程调用。
		safeClassifierPath := isSafeRelPath(classifier.Path)
		if safeClassifierPath == "" {
			a.writeLog("跳过不安全的 native jar 路径: %s", classifier.Path)
			continue
		}
		nativeJarPath := filepath.Join(mcDir, "libraries", safeClassifierPath)
		if !inspectRegularFile(nativeJarPath).trustable() {
			a.writeLog("native jar 不存在(跳过): %s", nativeJarPath)
			continue
		}
		extracted, err := extractNatives(nativeJarPath, nativesDir)
		if err != nil {
			a.writeLog("解压 native 失败: %s, %v", classifier.Path, err)
		} else if extracted > 0 {
			a.writeLog("解压 native: %s -> %d 个文件", classifier.Path, extracted)
		}
	}
}
