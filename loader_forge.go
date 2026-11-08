package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ===== 加载器安装 =====

func (a *App) extractForgeInstaller() (string, error) {
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	cacheDir := filepath.Join(tempDir, "qgl_cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", fmt.Errorf("创建缓存目录失败: %v", err)
	}

	installerPath := filepath.Join(cacheDir, "forge_installer.jar")

	if info, err := os.Stat(installerPath); err == nil && info.Size() == int64(len(forgeInstallerJar)) {
		return installerPath, nil
	}

	// 安装器 jar 走原子私有写：避免进程在落盘途中崩溃留下半截 jar，并拒绝沿既有
	// 符号链接把安装器写到缓存目录外。
	if err := secureWritePrivateFile(installerPath, forgeInstallerJar); err != nil {
		return "", fmt.Errorf("提取 ForgeInstaller 失败: %w", err)
	}

	return installerPath, nil
}

func isOldForge(versionStr string) bool {
	parts := strings.Split(versionStr, "-")
	verPart := parts[len(parts)-1]
	majorStr := strings.Split(verPart, ".")[0]
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return false
	}
	return major < 20
}

func (a *App) InstallForge(mcVersion string, forgeVersion string) error {
	if !isValidMCVersion(mcVersion) {
		return fmt.Errorf("无效的 Minecraft 版本格式")
	}
	if !isSafeFileName(forgeVersion) {
		return fmt.Errorf("无效的 Forge 版本格式")
	}

	a.writeLog("========== 开始安装 Forge: MC=%s, Forge=%s ==========", mcVersion, forgeVersion)

	fullVersion := forgeVersion
	if !strings.Contains(forgeVersion, mcVersion) {
		fullVersion = mcVersion + "-" + forgeVersion
	}
	a.writeLog("完整版本号: %s", fullVersion)

	mcDir := a.GetMinecraftDir()
	a.writeLog(".minecraft 目录: %s", mcDir)

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	installerPath := filepath.Join(tempDir, fmt.Sprintf("forge-%s-installer.jar", fullVersion))

	a.emitProgress("downloading", "下载 Forge 安装器", 0, 0)

	downloadURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/maven/net/minecraftforge/forge/%s/forge-%s-installer.jar",
		fullVersion, fullVersion,
	)
	a.writeLog("下载 URL: %s", downloadURL)

	os.Remove(installerPath)

	if err := a.downloadFile(downloadURL, installerPath, true); err != nil {
		a.writeLog("下载 Forge 安装器失败: %v", err)
		return fmt.Errorf("下载 Forge 安装器失败: %v", err)
	}

	if info, err := os.Stat(installerPath); err == nil {
		a.writeLog("安装器文件大小: %d 字节", info.Size())
	}

	isOld := isOldForge(fullVersion)
	a.writeLog("是否为旧版 Forge (<20): %v", isOld)

	if isOld {
		a.emitProgress("downloading", "安装旧版 Forge", 0, 0)
		return a.installOldForge(installerPath, mcDir, mcVersion)
	}

	a.emitProgress("downloading", "分析 Forge 支持库", 0, 0)

	if err := a.downloadForgeLibraries(installerPath, mcDir, mcVersion); err != nil {
		a.writeLog("下载 Forge 支持库失败（将继续尝试安装）: %v", err)
	}

	a.ensureLauncherProfiles(mcDir)

	oldVersions := a.getVersionFolderList(mcDir)

	a.emitProgress("downloading", "运行 Forge 安装器", 0, 0)

	err := a.runForgeInstaller(installerPath, mcDir)
	if err != nil {
		return err
	}

	newVersionFolder := a.findNewVersionFolder(mcDir, oldVersions, mcVersion, "forge")
	if newVersionFolder == "" {
		return fmt.Errorf("Forge 安装器运行完成但未找到版本文件夹")
	}

	if !a.validateVersionInstallation(newVersionFolder) {
		os.RemoveAll(newVersionFolder)
		return fmt.Errorf("Forge 安装验证失败：版本 JSON 无效")
	}

	fmt.Printf("Forge 安装成功: %s\n", filepath.Base(newVersionFolder))

	os.Remove(installerPath)

	return nil
}

func (a *App) installOldForge(installerPath string, mcDir string, mcVersion string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return fmt.Errorf("打开 Forge 安装器失败: %v", err)
	}
	defer r.Close()

	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				return fmt.Errorf("读取 install_profile.json 失败: %v", err)
			}
			if err := json.Unmarshal(data, &installProfile); err != nil {
				return fmt.Errorf("解析 install_profile.json 失败: %v", err)
			}
			break
		}
	}

	if installProfile == nil {
		return fmt.Errorf("安装器中未找到 install_profile.json")
	}

	targetVersion := ""
	if id, ok := installProfile["id"].(string); ok && id != "" {
		targetVersion = id
	}
	if targetVersion == "" {
		targetVersion = mcVersion + "-forge-unknown"
	}

	versionFolder := filepath.Join(mcDir, "versions", targetVersion)

	if err := os.MkdirAll(versionFolder, 0700); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}

	if installProfile["install"] == nil {
		jsonPath, _ := installProfile["json"].(string)
		if jsonPath == "" {
			return fmt.Errorf("install_profile.json 中缺少 json 字段")
		}
		// Zip Slip 防护：验证 ZIP 内路径不逃逸
		jsonPath = strings.TrimPrefix(jsonPath, "/")
		safeJSONPath := isSafeRelPath(jsonPath)
		if safeJSONPath == "" {
			return fmt.Errorf("安装器中 JSON 路径不安全: %s", jsonPath)
		}

		var versionJSONData []byte
		for _, f := range r.File {
			if f.Name == safeJSONPath {
				data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
				if err != nil {
					return fmt.Errorf("读取版本 JSON 失败: %v", err)
				}
				versionJSONData = data
				break
			}
		}

		if versionJSONData == nil {
			return fmt.Errorf("安装器中未找到 %s", safeJSONPath)
		}

		var versionJSON map[string]interface{}
		if err := json.Unmarshal(versionJSONData, &versionJSON); err != nil {
			return fmt.Errorf("解析版本 JSON 失败: %v", err)
		}
		versionJSON["id"] = targetVersion
		if versionJSON["inheritsFrom"] == nil {
			versionJSON["inheritsFrom"] = mcVersion
		}

		jsonFilePath := filepath.Join(versionFolder, targetVersion+".json")
		// 复用安装包 JSON 的 16MiB 读取上限作为落盘上限：输出来自该安装包，体积只会更小；
		// 走有界原子私有写，Marshal/超量/落盘任一失败都返回，不再吞错或留下半截文件。
		if err := writePrivateJSONBounded(jsonFilePath, versionJSON, maxInstallerJSONBytes); err != nil {
			return fmt.Errorf("保存版本 JSON 失败: %w", err)
		}

		r.Close()
		if err := a.extractMavenFiles(installerPath, mcDir); err != nil {
			fmt.Printf("解压 maven 文件失败（可能不影响启动）: %v\n", err)
		}
	} else {
		installInfo := installProfile["install"].(map[string]interface{})
		filePath, _ := installInfo["filePath"].(string)
		pathStr, _ := installInfo["path"].(string)

		if pathStr != "" && filePath != "" {
			// Zip Slip 防护：安装器给出的 Maven 路径与 zip 内条目名均走严格
			// 正斜杠相对路径白名单（拒盘符、反斜杠、冒号、保留设备名、.. 段）。
			safePathStr := SafeMavenRelPath(pathStr)
			safeFilePath := SafeMavenRelPath(filePath)
			if safePathStr == "" || safeFilePath == "" {
				return fmt.Errorf("安装器中路径不安全，跳过")
			}
			libPath := filepath.Join(mcDir, "libraries", filepath.FromSlash(safePathStr))
			// 内嵌库用 os.OpenFile 直接落盘，必须先确保父目录存在且收权 0700；
			// 原先忽略 MkdirAll 错误会让随后的 OpenFile 报一个更难定位的失败。
			if err := ensurePrivateDir(filepath.Dir(libPath)); err != nil {
				return fmt.Errorf("创建安装器内嵌库目录失败: %w", err)
			}

			for _, f := range r.File {
				if f.Name == safeFilePath {
					if f.UncompressedSize64 > uint64(maxInstallerLibBytes) {
						return fmt.Errorf("安装器内嵌库过大(解压炸弹防护): %s", safeFilePath)
					}
					// 内嵌库同样拒绝符号链接 / 设备等特殊条目，只允许普通文件落盘。
					if f.Mode()&unsafeEntryMode != 0 {
						return fmt.Errorf("安装器内嵌库是不允许的特殊类型: %s", safeFilePath)
					}
					rc, err := f.Open()
					if err != nil {
						break
					}
					out, err := os.OpenFile(libPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
					if err != nil {
						rc.Close()
						break
					}
					n, copyErr := io.Copy(out, io.LimitReader(rc, maxInstallerLibBytes+1))
					out.Close()
					rc.Close()
					if copyErr != nil || n > maxInstallerLibBytes {
						os.Remove(libPath)
						return fmt.Errorf("安装器内嵌库超过 %d 字节上限(解压炸弹防护): %s", maxInstallerLibBytes, safeFilePath)
					}
					break
				}
			}
		}

		versionInfo := installProfile["versionInfo"]
		if versionInfo != nil {
			vi := versionInfo.(map[string]interface{})
			vi["id"] = targetVersion
			if vi["inheritsFrom"] == nil {
				vi["inheritsFrom"] = mcVersion
			}
			jsonFilePath := filepath.Join(versionFolder, targetVersion+".json")
			// 旧版 Forge 分支此前完全忽略序列化与落盘错误且为非原子写，统一收口到
			// 有界原子私有写，任一失败都向上返回（安装后续会校验，避免带病继续）。
			if err := writePrivateJSONBounded(jsonFilePath, vi, maxInstallerJSONBytes); err != nil {
				return fmt.Errorf("保存版本 JSON 失败: %w", err)
			}
		}
	}

	if !a.validateVersionInstallation(versionFolder) {
		os.RemoveAll(versionFolder)
		return fmt.Errorf("旧版 Forge 安装验证失败")
	}

	fmt.Printf("旧版 Forge 安装成功: %s\n", targetVersion)

	os.Remove(installerPath)

	return nil
}

// Forge/NeoForge 安装器是从镜像下载的不受信任 JAR，其中 maven/ 条目会被
// 解压到 libraries。统一走 zipextract 安全解压内核：Zip Slip、符号链接等特殊
// 条目、条目数 / 单条目 / 总量上限全部预检，落盘采用临时文件 + 原子替换。
// 正常的依赖 jar 只有几 MB 到几十 MB，正常数据永远碰不到这些阈值。
const (
	maxMavenEntryBytes int64 = 256 << 20 // 单个 maven 条目 256 MiB
	maxMavenTotalBytes int64 = 2 << 30   // maven 解压总量 2 GiB
	maxMavenEntries          = 100000    // maven 条目数上限（inode 耗尽防护）
)

func (a *App) extractMavenFiles(installerPath string, mcDir string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return err
	}
	defer r.Close()

	libsDir := filepath.Join(mcDir, "libraries")
	lim := zipExtractLimits{
		EntryMax:   maxMavenEntryBytes,
		TotalMax:   maxMavenTotalBytes,
		MaxEntries: maxMavenEntries,
	}
	n, count, err := extractZipPrefixes(r.File, libsDir, []string{"maven/"}, lim, a.writeLog)
	if err != nil {
		return err
	}
	a.writeLog("maven 解压完成: %d 个文件，共 %d 字节", count, n)
	return nil
}

func (a *App) downloadForgeLibraries(installerPath string, mcDir string, mcVersion string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return fmt.Errorf("打开安装器失败: %v", err)
	}
	defer r.Close()

	var profileData, versionData map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" || f.Name == "version.json" {
			// 安装器 JSON 不受信任，限 16 MiB 防解压炸弹；超限/损坏就跳过该文件。
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				fmt.Printf("跳过安装器条目 %s: %v\n", f.Name, err)
				continue
			}
			var target map[string]interface{}
			if err := json.Unmarshal(data, &target); err != nil {
				continue
			}
			if f.Name == "install_profile.json" {
				profileData = target
			} else {
				versionData = target
			}
		}
	}

	if profileData == nil {
		return fmt.Errorf("未找到 install_profile.json")
	}

	var allLibs []interface{}
	if libs, ok := profileData["libraries"].([]interface{}); ok {
		allLibs = append(allLibs, libs...)
	}
	if versionData != nil {
		if libs, ok := versionData["libraries"].([]interface{}); ok {
			allLibs = append(allLibs, libs...)
		}
	}

	libsDir := filepath.Join(mcDir, "libraries")
	for _, lib := range allLibs {
		libMap, ok := lib.(map[string]interface{})
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
		sha1, _ := artifact["sha1"].(string)
		if url == "" || path == "" {
			continue
		}

		// 安装器不可信：库 URL 必须落在官方/可信 Maven 主机白名单内，
		// 否则攻击者可借安装器把任意 jar 拉进 classpath（供应链 RCE）。
		if !isAllowedMavenLibURL(url) {
			fmt.Printf("跳过非可信 Maven 主机的库（防止供应链投毒）: %s\n", url)
			continue
		}

		url = rewriteMavenLibURLToBMCL(url)

		// Zip Slip 防护：库路径走严格 Maven 相对路径白名单
		safePath := SafeMavenRelPath(path)
		if safePath == "" {
			fmt.Printf("跳过不安全的库路径: %s\n", path)
			continue
		}
		destPath := filepath.Join(libsDir, filepath.FromSlash(safePath))

		// 走带官方 sha1 的下载：已存在的库也会经侧车摘要链复核，
		// 避免“文件在就直接信任”导致被替换的 jar 被加载。
		// 个别安装器确实缺 sha1 字段时仍下载（主机已白名单），但不再自行跳过校验。
		if err := a.downloadVerifiedFile(url, destPath, strings.TrimSpace(sha1), false); err != nil {
			fmt.Printf("下载/校验支持库失败 %s: %v\n", path, err)
		}
	}

	dataSection, hasData := profileData["data"].(map[string]interface{})
	if !hasData {
		fmt.Printf("未找到 data 字段（跳过 Mappings 下载）\n")
	} else if _, hasMojmaps := dataSection["MOJMAPS"]; hasMojmaps {
		fmt.Printf("检测到新版 Forge，需要下载 Mappings 文件\n")
		a.downloadForgeMappings(mcDir, mcVersion, installerPath)
	} else {
		fmt.Printf("未找到 MOJMAPS 字段（跳过 Mappings 下载）\n")
	}

	return nil
}

// ensureForgeMappings 确保 Forge 新版需要的 Mappings 文件存在
// 安全修复：移除 PowerShell 命令，改用 Go 原生 HTTP 下载，防止命令注入
// maxMappingsDownloadBytes 限制 Forge mappings 下载体积为 1 GiB，正常映射文件只有十几 MB，只有明显炸磁盘的响应才会触发。
