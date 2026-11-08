package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
const maxMappingsDownloadBytes int64 = 1 << 30

func (a *App) ensureForgeMappings(installerPath string, mcDir string) {
	a.writeLog("===== 开始检查 Forge Mappings 文件 =====")

	r, err := zip.OpenReader(installerPath)
	if err != nil {
		a.writeLog("无法打开安装器（跳过 Mappings 检查）: %v", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	var mcVersion string
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				a.writeLog("读取 install_profile.json 失败(条目过大或损坏，跳过): %v", err)
				break
			}
			json.Unmarshal(data, &installProfile)

			if minecraftVal, ok := installProfile["minecraft"]; ok {
				if mv, ok := minecraftVal.(string); ok {
					mcVersion = mv
					a.writeLog("找到 mcVersion: %s", mcVersion)
				}
			}
			break
		}
	}

	if installProfile == nil || mcVersion == "" {
		a.writeLog("未找到 mcVersion（跳过 Mappings 检查）")
		return
	}

	dataSection, ok := installProfile["data"].(map[string]interface{})
	if !ok {
		a.writeLog("未找到 data 字段（跳过 Mappings 检查）")
		return
	}

	mojmapsData, ok := dataSection["MOJMAPS"].(map[string]interface{})
	if !ok {
		a.writeLog("未找到 MOJMAPS 字段（跳过 Mappings 检查）")
		return
	}

	clientValue, ok := mojmapsData["client"].(string)
	if !ok || clientValue == "" {
		a.writeLog("未找到 MOJMAPS.client 字段（跳过 Mappings 检查）")
		return
	}

	clientValue = strings.Trim(clientValue, "[]")
	atIndex := strings.Index(clientValue, "@")
	if atIndex == -1 {
		a.writeLog("MOJMAPS.client 格式错误（跳过 Mappings 检查）")
		return
	}

	originalName := clientValue[:atIndex]
	extension := clientValue[atIndex+1:]

	// 坐标与扩展名来自不可信的安装器 JSON，不能再用 Split 后原样拼 filepath.Join，
	// 否则 ".." 段 / 分隔符 / 带穿越的扩展名会把 mappings 写到 libraries 之外。
	// 统一走严格白名单推导，并强制结果落在 <mcDir>/libraries 内。
	targetPath, ok := SafeMojmapsMappingsPath(mcDir, originalName, extension)
	if !ok {
		a.writeLog("MOJMAPS.client 坐标或扩展名未通过路径白名单（跳过 Mappings 检查）")
		return
	}

	a.writeLog("目标路径: %s", targetPath)

	if _, err := os.Stat(targetPath); err == nil {
		a.writeLog("Mappings 文件已存在: %s", targetPath)
		return
	}

	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	var rawJSON map[string]interface{}
	if err := readLocalJSONBounded(jsonPath, &rawJSON, 0, "原版版本 JSON"); err != nil {
		a.writeLog("无法读取/解析原版版本 JSON: %v", err)
		return
	}

	downloads, _ := rawJSON["downloads"].(map[string]interface{})
	if downloads == nil {
		a.writeLog("未找到 downloads 字段")
		return
	}

	clientMappings, _ := downloads["client_mappings"].(map[string]interface{})
	if clientMappings == nil {
		a.writeLog("未找到 client_mappings 字段")
		return
	}

	mappingsURL, _ := clientMappings["url"].(string)
	if mappingsURL == "" {
		a.writeLog("未找到 client_mappings URL")
		return
	}

	// 安全验证：只允许 HTTPS
	if !isHTTPSURL(mappingsURL) {
		a.writeLog("跳过不安全的下载 URL（非 HTTPS）: %s", mappingsURL)
		return
	}

	mappingsURL = rewriteMappedDataURLToBMCL(mappingsURL)

	a.writeLog("使用 Go 原生 HTTP 下载 Mappings 文件...")
	a.writeLog("下载 URL: %s", mappingsURL)
	a.writeLog("保存到: %s", targetPath)

	// 这里是手写流式下载（os.OpenFile 直接落盘），由本处显式确保目录 0700 并收权。
	if err := ensurePrivateDir(filepath.Dir(targetPath)); err != nil {
		a.writeLog("创建目标目录失败: %v", err)
		return
	}

	// 安全修复：使用 Go 原生 HTTP 下载，替代 PowerShell 命令，防止命令注入
	client := safeHTTPClient()
	req, err := http.NewRequest("GET", mappingsURL, nil)
	if err != nil {
		a.writeLog("创建下载请求失败: %v", err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		a.writeLog("下载失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.writeLog("下载失败: HTTP %d", resp.StatusCode)
		return
	}

	out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		a.writeLog("创建目标文件失败: %v", err)
		return
	}
	defer out.Close()

	limited := io.LimitReader(resp.Body, maxMappingsDownloadBytes+1)
	n, copyErr := io.Copy(out, limited)
	if copyErr != nil || n > maxMappingsDownloadBytes {
		a.writeLog("mappings 文件超过 %d 字节上限，中止下载", maxMappingsDownloadBytes)
		os.Remove(targetPath)
		return
	}

	fileInfo, statErr := os.Stat(targetPath)
	if statErr != nil {
		a.writeLog("下载后验证文件失败: %v", statErr)
		return
	}

	if fileInfo.Size() == 0 {
		a.writeLog("下载的文件为空！删除空文件")
		os.Remove(targetPath)
		return
	}

	a.writeLog("Mappings 下载成功! 文件大小: %d 字节, 路径: %s", fileInfo.Size(), targetPath)
}

func (a *App) downloadForgeMappings(mcDir string, mcVersion string, installerPath string) {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		fmt.Printf("无法打开安装器（跳过 Mappings 下载）: %v\n", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				fmt.Printf("读取 install_profile.json 失败(条目过大或损坏，跳过): %v\n", err)
				break
			}
			json.Unmarshal(data, &installProfile)
			break
		}
	}

	if installProfile == nil {
		fmt.Printf("未找到 install_profile.json（跳过 Mappings 下载）\n")
		return
	}

	dataSection, ok := installProfile["data"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 data 字段（跳过 Mappings 下载）\n")
		return
	}

	mojmapsData, ok := dataSection["MOJMAPS"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 MOJMAPS 字段（跳过 Mappings 下载）\n")
		return
	}

	mcpVersion, ok := mojmapsData["version"].(string)
	if !ok || mcpVersion == "" {
		fmt.Printf("未找到 MOJMAPS.version 字段（跳过 Mappings 下载）\n")
		return
	}

	fmt.Printf("检测到 Forge MOJMAPS: %s\n", mcpVersion)

	targetPath, ok := SafeMappingsVersionPath(mcDir, mcpVersion)
	if !ok {
		fmt.Printf("MOJMAPS.version 未通过落盘路径白名单（跳过 Mappings 下载）: %s\n", mcpVersion)
		return
	}

	if _, err := os.Stat(targetPath); err == nil {
		fmt.Printf("Mappings 文件已存在: %s\n", targetPath)
		return
	}

	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	var rawJSON map[string]interface{}
	if err := readLocalJSONBounded(jsonPath, &rawJSON, 0, "原版版本 JSON"); err != nil {
		fmt.Printf("无法读取/解析原版版本 JSON（跳过 Mappings 下载）: %v\n", err)
		return
	}

	downloads, ok := rawJSON["downloads"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 downloads 字段（跳过 Mappings 下载）\n")
		return
	}

	clientMappings, ok := downloads["client_mappings"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 client_mappings 字段（跳过 Mappings 下载）\n")
		return
	}

	mappingsURL, _ := clientMappings["url"].(string)
	if mappingsURL == "" {
		fmt.Printf("未找到 client_mappings URL（跳过 Mappings 下载）\n")
		return
	}

	if !isHTTPSURL(mappingsURL) {
		fmt.Printf("跳过不安全的下载 URL（非 HTTPS）: %s\n", mappingsURL)
		return
	}

	mappingsURL = rewriteMappedDataURLToBMCL(mappingsURL)

	tempPath := targetPath + ".tmp"
	_ = os.Remove(tempPath)
	fmt.Printf("下载 Forge Mappings (%s): %s\n", mcpVersion, mappingsURL)
	if err := a.downloadFileBounded(mappingsURL, tempPath, false, maxMappingsDownloadBytes); err != nil {
		os.Remove(tempPath)
		fmt.Printf("下载 Mappings 失败: %v\n", err)
		return
	}

	if err := os.Rename(tempPath, targetPath); err != nil {
		os.Remove(tempPath)
		fmt.Printf("重命名 Mappings 文件失败: %v\n", err)
		return
	}

	fmt.Printf("Mappings 下载成功: %s\n", targetPath)
}

func (a *App) ensureLauncherProfiles(mcDir string) {
	profilesPath := filepath.Join(mcDir, "launcher_profiles.json")
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		profiles := map[string]interface{}{
			"profiles": map[string]interface{}{},
		}
		// launcher_profiles.json 是启动器状态文件，有界原子私有写防半截写与符号链接写穿；
		// 序列化错误也不再被丢弃。
		if err := writePrivateJSON(profilesPath, profiles); err != nil {
			fmt.Printf("创建 launcher_profiles.json 失败: %v\n", err)
		}
	}
}

func (a *App) getVersionFolderList(mcDir string) map[string]bool {
	versionsDir := filepath.Join(mcDir, "versions")
	result := map[string]bool{}

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if entry.IsDir() {
			result[entry.Name()] = true
		}
	}

	return result
}

func (a *App) runForgeInstaller(installerPath string, mcDir string) error {
	a.writeLog("===== 开始运行 ForgeInstaller =====")

	a.ensureForgeMappings(installerPath, mcDir)

	bbInstallerPath, err := a.extractForgeInstaller()
	if err != nil {
		a.writeLog("提取 ForgeInstaller 失败: %v", err)
		return err
	}
	a.writeLog("ForgeInstaller 路径: %s", bbInstallerPath)
	a.writeLog("Forge 安装器路径: %s", installerPath)

	javaEntry, err := a.selectJavaForInstaller()
	if err != nil {
		a.writeLog("选择 Java 失败: %v", err)
		return fmt.Errorf("选择 Java 失败: %v", err)
	}
	a.writeLog("使用 Java: %s (版本: %s, 主版本: %d)", javaEntry.Path, javaEntry.Version, javaEntry.MajorVer)

	classpath := bbInstallerPath + ";" + installerPath

	args := []string{}
	if javaEntry.MajorVer >= 9 {
		args = append(args, "--add-exports", "cpw.mods.bootstraplauncher/cpw.mods.bootstraplauncher=ALL-UNNAMED")
	}
	args = append(args, "-cp", classpath, "com.bangbang93.ForgeInstaller", mcDir)

	a.writeLog("完整命令: %s %s", javaEntry.Path, strings.Join(args, " "))

	// 启动前对安装器 JVM 做目标审计：java 可执行、工作目录、绝对 classpath 的目录归属
	// （bbInstaller / installer 各自的父目录 + mcDir）、主类与程序参数，阻止任何指向
	// UNC / 目录穿越 / 允许目录之外的 jar/classpath。
	forgeRoots := []string{mcDir, filepath.Dir(bbInstallerPath), filepath.Dir(installerPath)}
	forgeAudit := AuditExternalJVM(ExternalJVMPlan{
		JavaExe:      javaEntry.Path,
		WorkDir:      mcDir,
		Classpath:    []string{bbInstallerPath, installerPath},
		MainClass:    "com.bangbang93.ForgeInstaller",
		ProgramArgs:  []string{mcDir},
		AllowedRoots: forgeRoots,
	})
	if forgeAudit.HasCritical() {
		return fmt.Errorf("Forge 安装器启动审计未通过: %s", forgeAudit.FirstCriticalCode())
	}

	cmd := exec.Command(javaEntry.Path, args...)
	cmd.Dir = mcDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Forge 安装器本身是个独立 JVM：不下发净化环境就会继承
	// JAVA_TOOL_OPTIONS 一族，绕过 JVM 参数过滤注入 javaagent。
	a.applySanitizedJVMEnv(cmd, "ForgeInstaller", nil)

	output, runErr := cmd.CombinedOutput()
	outputStr := string(output)

	a.writeLog("----- ForgeInstaller 输出开始 -----")
	if outputStr != "" {
		for _, line := range strings.Split(outputStr, "\n") {
			a.writeLog("  %s", line)
		}
	} else {
		a.writeLog("  (无输出)")
	}
	a.writeLog("----- ForgeInstaller 输出结束 -----")
	if runErr != nil {
		a.writeLog("进程退出错误: %v", runErr)
	}

	lines := strings.Split(outputStr, "\n")
	var lastLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			lastLines = append(lastLines, line)
		}
	}

	foundTrue := false
	checkCount := 4
	if len(lastLines) < checkCount {
		checkCount = len(lastLines)
	}
	for _, line := range lastLines[len(lastLines)-checkCount:] {
		if line == "true" {
			foundTrue = true
			break
		}
	}

	if foundTrue {
		a.writeLog("检测到安装器成功标志 'true'，安装成功")
		return nil
	}

	a.writeLog("未检测到安装器成功标志 'true'，安装失败")

	if runErr != nil {
		errMsg := fmt.Errorf("Forge 安装器运行失败\nJava: %s (v%d)\n错误: %v\n\n完整输出:\n%s",
			javaEntry.Path, javaEntry.MajorVer, runErr, outputStr)
		a.writeLog("Forge 安装最终失败: %v", errMsg)
		return errMsg
	}

	errMsg := fmt.Errorf("Forge 安装器未返回成功标志\nJava: %s (v%d)\n\n完整输出:\n%s",
		javaEntry.Path, javaEntry.MajorVer, outputStr)
	a.writeLog("Forge 安装最终失败: %v", errMsg)
	return errMsg
}

func (a *App) findNewVersionFolder(mcDir string, oldVersions map[string]bool, mcVersion string, loaderType string) string {
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() || oldVersions[entry.Name()] {
			continue
		}
		name := entry.Name()
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, loaderType) && strings.Contains(nameLower, strings.ToLower(mcVersion)) {
			versionFolder := filepath.Join(versionsDir, name)
			if a.validateVersionInstallation(versionFolder) {
				return versionFolder
			}
		}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, loaderType) && strings.Contains(nameLower, strings.ToLower(mcVersion)) {
			versionFolder := filepath.Join(versionsDir, name)
			if a.validateVersionInstallation(versionFolder) {
				return versionFolder
			}
		}
	}

	return ""
}
