package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (a *App) DownloadVersion(versionID string, versionURL string, customName string) error {
	mcDir := a.getMinecraftDir()
	// customName 既可能来自前端，也可能来自 .mrpack 清单里的 dependencies.minecraft
	// （installModpack 原样透传到这里），属于外部输入，必须走严格名单段内核，防止
	// 形如 "../../evil" / "CON" / "a\x00b" 的值把版本文件写到 versions 目录之外。
	safeName, why := SafeVersionComponent(customName)
	if why != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"minecraft", "拒绝非法版本目录名: "+describeNameReject(why))
		return fmt.Errorf("无效的版本名称: %s", describeNameReject(why))
	}
	customName = safeName
	versionDir := filepath.Join(mcDir, "versions", customName)
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}
	a.emitProgress("downloading", customName+".json", 0, 0)
	jsonURL := rewriteLauncherURLToBMCL(versionURL)
	if !urlOnTrustedHost(jsonURL, allowedVersionMetaHosts) {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityCritical, auditActionBlocked,
			"version-manifest", "版本清单地址不在可信元数据主机白名单内")
		return fmt.Errorf("版本清单地址不在可信元数据主机白名单内")
	}
	jsonPath := filepath.Join(versionDir, customName+".json")
	if err := a.downloadFileBounded(jsonURL, jsonPath, false, maxMetadataJSONBytes); err != nil {
		return fmt.Errorf("下载版本 JSON 失败: %v", err)
	}
	jsonData, err := readBoundedFile(jsonPath, maxMetadataJSONBytes)
	if err != nil {
		return fmt.Errorf("读取版本 JSON 失败: %v", err)
	}
	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	// 先把清单内 URL 归一化为真正发起请求时的地址（BMCLAPI 重写是确定性、受信任的），
	// 白名单审计必须针对“实际抓取主机”，否则会误杀走 launcher.mojang.com 的老清单，
	// 也避免攻击者靠“审计看 A、实际请求 B”的差异绕过。
	if versionJSON.Downloads != nil {
		if versionJSON.Downloads.Client != nil {
			versionJSON.Downloads.Client.URL = rewriteLauncherURLToBMCL(versionJSON.Downloads.Client.URL)
		}
		if versionJSON.Downloads.Server != nil {
			versionJSON.Downloads.Server.URL = rewriteLauncherURLToBMCL(versionJSON.Downloads.Server.URL)
		}
	}
	for i := range versionJSON.Libraries {
		dl := versionJSON.Libraries[i].Downloads
		if dl == nil {
			continue
		}
		if dl.Artifact != nil {
			dl.Artifact.URL = rewriteLauncherURLToBMCL(dl.Artifact.URL)
		}
		for _, art := range dl.Classifiers {
			if art != nil {
				art.URL = rewriteLauncherURLToBMCL(art.URL)
			}
		}
	}
	if versionJSON.AssetIndex != nil {
		versionJSON.AssetIndex.URL = rewriteLauncherURLToBMCL(versionJSON.AssetIndex.URL)
	}
	// 版本 JSON 来自可由前端指定的第三方 versionURL，client / library / native 的
	// url/path/sha1 全部不受信任：下载主机必须落在官方 / 镜像白名单，可执行产物必须
	// 带合法 SHA1，库路径必须是严格 Maven 相对路径，资源索引 ID 必须是单段安全名。
	// critical 一律拒绝下载（防止攻击者把 jar 指向自己的服务器落进 classpath）。
	manifestFindings := auditVersionManifest(&versionJSON)
	for i := range manifestFindings {
		f := &manifestFindings[i]
		if f.Severity == manifestCritical {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityCritical, auditActionBlocked,
				"version-manifest", f.Field+": "+f.Detail)
		} else {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionDetected,
				"version-manifest", f.Field+": "+f.Detail)
		}
	}
	if manifestHasCritical(manifestFindings) {
		return manifestCriticalError(manifestFindings)
	}
	if versionJSON.Downloads != nil && versionJSON.Downloads.Client != nil {
		client := versionJSON.Downloads.Client
		clientURL := rewriteLauncherURLToBMCL(client.URL)
		jarPath := filepath.Join(versionDir, customName+".jar")
		a.emitProgress("downloading", customName+".jar", 0, client.Size)
		if err := a.downloadVerifiedFile(clientURL, jarPath, client.SHA1, true); err != nil {
			return fmt.Errorf("下载客户端 jar 失败: %v", err)
		}
	}
	a.emitProgress("downloading", "库文件", 0, 0)
	for _, lib := range versionJSON.Libraries {
		if lib.Downloads == nil {
			continue
		}
		if lib.Downloads.Artifact != nil {
			artifact := lib.Downloads.Artifact
			// Zip Slip 防护：库路径走严格 Maven 相对路径白名单（拒盘符/反斜杠/冒号）
			safePath := SafeMavenRelPath(artifact.Path)
			if safePath == "" {
				fmt.Printf("跳过不安全的库路径: %s\n", artifact.Path)
				continue
			}
			libPath := filepath.Join(mcDir, "libraries", filepath.FromSlash(safePath))
			libURL := rewriteLauncherURLToBMCL(artifact.URL)
			a.emitProgress("downloading", filepath.Base(artifact.Path), 0, artifact.Size)
			if err := a.downloadVerifiedFile(libURL, libPath, artifact.SHA1, false); err != nil {
				fmt.Printf("下载库文件失败(跳过): %s, %v\n", artifact.Path, err)
			}
		}
		if lib.Natives != nil {
			// 仍只选择 Windows 系列分类器，但按真实架构挑选 windows-x86 /
			// windows-64 / windows-arm64，并正确替换 ${arch}（旧实现恒为 "64"，
			// 在 32 位 / ARM64 上会取错本地库）。
			winEnv := ruleEnv{osName: "windows", osArch: currentRuleEnv().osArch}
			nativeKey, ok := resolveWindowsNativeKey(lib.Natives, winEnv)
			if !ok {
				continue
			}
			if lib.Downloads.Classifiers == nil {
				continue
			}
			classifier, ok := lib.Downloads.Classifiers[nativeKey]
			if !ok || classifier == nil {
				continue
			}
			// Zip Slip 防护：native 路径走严格 Maven 相对路径白名单
			safeClassPath := SafeMavenRelPath(classifier.Path)
			if safeClassPath == "" {
				fmt.Printf("跳过不安全的 native 路径: %s\n", classifier.Path)
				continue
			}
			nativePath := filepath.Join(mcDir, "libraries", filepath.FromSlash(safeClassPath))
			nativeURL := rewriteLauncherURLToBMCL(classifier.URL)
			a.emitProgress("downloading", filepath.Base(classifier.Path), 0, classifier.Size)
			if err := a.downloadVerifiedFile(nativeURL, nativePath, classifier.SHA1, false); err != nil {
				fmt.Printf("下载 native 失败: %s, %v\n", classifier.Path, err)
			}
		}
	}
	if versionJSON.AssetIndex != nil {
		assetIndexRef := versionJSON.AssetIndex
		// 资产索引 ID 来自外部版本 JSON，会直接拼进文件路径，必须强制为
		// 单段安全名，防止 "1.21/../../x.json" 之类路径穿越或落到非预期位置。
		safeIndexID := SafeSimpleName(assetIndexRef.ID)
		if safeIndexID == "" {
			return fmt.Errorf("资产索引 ID 不安全，拒绝继续: %q", assetIndexRef.ID)
		}
		assetIndexDir := filepath.Join(mcDir, "assets", "indexes")
		assetIndexPath := filepath.Join(assetIndexDir, safeIndexID+".json")
		assetIndexURL := rewriteLauncherURLToBMCL(assetIndexRef.URL)
		a.emitProgress("downloading", "资源索引", 0, 0)
		if err := a.downloadFileBounded(assetIndexURL, assetIndexPath, false, maxMetadataJSONBytes); err != nil {
			fmt.Printf("下载资源索引失败: %v\n", err)
		} else {
			assetIndexData, err := readBoundedFile(assetIndexPath, maxMetadataJSONBytes)
			if err == nil {
				var assetIndex AssetIndex
				if json.Unmarshal(assetIndexData, &assetIndex) == nil {
					totalAssets := len(assetIndex.Objects)
					count := 0
					for name, obj := range assetIndex.Objects {
						count++
						// 对象哈希既拼下载 URL 也拼本地 objects/xx/<40hex> 路径，
						// 且会做 hash[:2] 切片：必须严格是 40 位小写十六进制，
						// 否则既可能路径穿越，也会因长度不足直接 panic 崩溃。
						if !IsLowerHex(obj.Hash, 40) {
							a.writeLog("跳过哈希非法的资源 %s: %q", name, obj.Hash)
							continue
						}
						// 对象 key 会原样拼进下载 URL，拒绝穿越段 / 反斜杠 / 控制字符。
						safeName, whyName := validateAssetObjectName(name)
						if whyName != aoOK {
							a.writeLog("跳过资源名非法的对象 %q: %s", name, describeAssetReject(whyName))
							continue
						}
						hash := obj.Hash
						subHash := hash[:2]
						assetURL := rewriteLauncherURLToBMCL(fmt.Sprintf("https://launcher.mojang.com/v1/objects/%s/%s", hash, safeName))
						assetPath := filepath.Join(mcDir, "assets", "objects", subHash, hash)
						a.emitProgress("downloading", fmt.Sprintf("资源 %d/%d", count, totalAssets), int64(count), int64(totalAssets))
						if !inspectRegularFile(assetPath).trustable() {
							if !a.downloadAssetObject([]string{assetURL}, assetPath, hash) {
								fmt.Printf("下载资源失败(跳过): %s\n", name)
							}
						}
					}
				}
			}
		}
	}
	a.emitProgress("extracting", "natives", 0, 0)
	nativesDir := filepath.Join(versionDir, customName+"-natives")
	if err := os.MkdirAll(nativesDir, 0700); err != nil {
		return fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, &versionJSON)
	nativesEntries, err := os.ReadDir(nativesDir)
	if err == nil && len(nativesEntries) == 0 {
		a.writeLog("警告: natives 目录为空，游戏可能无法启动")
	}
	a.emitProgress("completed", "", 100, 100)
	return nil
}

// checkFileHash 校验文件完整性（SHA1，用于验证 Mojang manifest 提供的哈希）
