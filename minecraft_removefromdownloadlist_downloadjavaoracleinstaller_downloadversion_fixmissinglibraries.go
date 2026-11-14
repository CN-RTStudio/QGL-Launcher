package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

)

func (a *App) fixMissingLibraries(mcDir string, versionJSON *VersionJSON) {
	libsDir := filepath.Join(mcDir, "libraries")
	missingCount := 0
	downloadedCount := 0
	hashFailCount := 0

	// 预统计需要检查的库数量（用于进度百分比）
	totalLibs := 0
	for _, lib := range versionJSON.Libraries {
		if a.shouldIncludeLib(lib) {
			totalLibs++
		}
	}
	processedLibs := 0
	var lastLibEmit time.Time

	for _, lib := range versionJSON.Libraries {
		// 跳过不适用于当前平台的库
		if !a.shouldIncludeLib(lib) {
			continue
		}

		// 每 300ms 上报一次库文件检查进度（含百分比，避免用户以为卡死）
		processedLibs++
		if time.Since(lastLibEmit) > 300*time.Millisecond {
			lastLibEmit = time.Now()
			pct := 0
			if totalLibs > 0 {
				pct = processedLibs * 100 / totalLibs
			}
			a.emitFixProgress(fmt.Sprintf("补全文件 %d/%d (%d%%)", processedLibs, totalLibs, pct), int64(processedLibs), int64(totalLibs))
		}

		// 处理 natives 库：确保 native jar 文件存在
		if lib.Natives != nil {
			nativeKey, ok := lib.Natives["windows"]
			if !ok {
				continue
			}
			// 替换 ${arch} 占位符
			nativeKey = strings.ReplaceAll(nativeKey, "${arch}", "64")

			var nativePath string
			var nativeURL string
			var nativeSHA1 string

			if lib.Downloads != nil && lib.Downloads.Classifiers != nil {
				classifier, ok := lib.Downloads.Classifiers[nativeKey]
				if ok && classifier != nil {
					nativePath = filepath.Join(libsDir, classifier.Path)
					nativeURL = classifier.URL
					nativeSHA1 = classifier.SHA1
				}
			}

			if nativePath == "" {
				// 从 Maven 坐标推算路径
				nativePath = mavenNameToPath(lib.Name+"-"+nativeKey, libsDir)
			}

			if nativePath == "" {
				continue
			}

			// 检查 native jar 是否存在且校验通过
			if a.checkFileHash(nativePath, nativeSHA1) {
				continue
			}

			missingCount++

			// 尝试下载 native jar
			if nativeURL != "" {
				urls := a.getMirrorURLs(nativeURL)
				if a.downloadFromMirrors(urls, nativePath) {
					downloadedCount++
					a.writeLog("补全 native 库: %s", filepath.Base(nativePath))
				} else {
					a.writeLog("补全 native 库失败: %s", filepath.Base(nativePath))
				}
			}
			continue
		}

		// 确定库文件路径、URL、SHA1
		var libPath string
		var downloadURL string
		var expectedSHA1 string

		if lib.Downloads != nil && lib.Downloads.Artifact != nil && lib.Downloads.Artifact.Path != "" {
			libPath = filepath.Join(libsDir, lib.Downloads.Artifact.Path)
			downloadURL = lib.Downloads.Artifact.URL
			expectedSHA1 = lib.Downloads.Artifact.SHA1
		} else if lib.JarPath != "" {
			libPath = filepath.Join(libsDir, lib.JarPath)
			downloadURL = lib.URL
		} else if lib.Name != "" {
			libPath = mavenNameToPath(lib.Name, libsDir)
			downloadURL = ""
		}

		if libPath == "" {
			continue
		}

		// 检查文件是否存在且 SHA1 校验通过（参考 PCL 的 FileChecker）
		if a.checkFileHash(libPath, expectedSHA1) {
			continue
		}

		// 文件不存在或 SHA1 不匹配
		if _, err := os.Stat(libPath); err == nil && expectedSHA1 == "" {
			continue // 文件存在且无 SHA1 要求，跳过
		}

		if _, err := os.Stat(libPath); err == nil && expectedSHA1 != "" {
			hashFailCount++
			a.writeLog("库文件 SHA1 校验失败，重新下载: %s", filepath.Base(libPath))
		} else {
			missingCount++
		}

		// 尝试下载
		if downloadURL == "" {
			// 没有 URL，尝试从 Maven 坐标构建 URL
			downloadURL = mavenNameToURL(lib.Name)
		}

		if downloadURL == "" {
			a.writeLog("库文件缺失且无下载地址: %s", libPath)
			continue
		}

		// 获取多个镜像 URL（参考 PCL 的多源下载）
		urls := a.getMirrorURLs(downloadURL)

		// 删除损坏的文件
		if _, err := os.Stat(libPath); err == nil {
			os.Remove(libPath)
		}

		os.MkdirAll(filepath.Dir(libPath), 0755)
		if a.downloadFromMirrors(urls, libPath) {
			downloadedCount++
			a.writeLog("补全库文件: %s", filepath.Base(libPath))
		} else {
			a.writeLog("补全库文件失败: %s", filepath.Base(libPath))
		}
	}

	// 补全游戏主 jar（参考 PCL 的 DlClientJarGet）
	jarName := versionJSON.Jar
	if jarName == "" {
		jarName = versionJSON.InheritsFrom
	}
	if jarName == "" {
		jarName = versionJSON.ID
	}
	versionJar := filepath.Join(mcDir, "versions", jarName, jarName+".jar")
	var jarSHA1 string
	if versionJSON.Downloads != nil && versionJSON.Downloads.Client != nil {
		jarSHA1 = versionJSON.Downloads.Client.SHA1
	}

	if !a.checkFileHash(versionJar, jarSHA1) {
		if versionJSON.Downloads != nil && versionJSON.Downloads.Client != nil && versionJSON.Downloads.Client.URL != "" {
			os.MkdirAll(filepath.Dir(versionJar), 0755)
			url := versionJSON.Downloads.Client.URL
			urls := a.getMirrorURLs(url)
			// 替换特殊路径
			for i, u := range urls {
				urls[i] = strings.Replace(u, "https://launcher.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
				urls[i] = strings.Replace(urls[i], "https://piston-data.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
				urls[i] = strings.Replace(urls[i], "https://piston-meta.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
			}
			if a.downloadFromMirrors(urls, versionJar) {
				downloadedCount++
				a.writeLog("补全游戏 jar: %s", jarName)
			} else {
				a.writeLog("补全游戏 jar 失败: %s", jarName)
			}
		}
	}

	// 补全资源文件索引（参考 PCL 的 DlClientAssetIndexGet）
	a.fixAssetsIndex(mcDir, versionJSON)

	if missingCount > 0 || hashFailCount > 0 {
		a.writeLog("库文件补全完成: 缺失 %d 个, SHA1 不匹配 %d 个, 成功下载 %d 个", missingCount, hashFailCount, downloadedCount)
	}
}

// checkFileHash 检查文件是否存在且 SHA1 校验通过（参考 PCL 的 FileChecker.Check）
// 如果 SHA1 为空，只检查文件是否存在
