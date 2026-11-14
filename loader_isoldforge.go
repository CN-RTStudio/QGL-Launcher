package main

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

)

// ===== 日志功能 =====

// writeLog 将信息写入日志文件（用户可随时查看和复制）

func isOldForge(versionStr string) bool {
	// versionStr 类似 "1.16.5-34.1.0" 或 "34.1.0"
	parts := strings.Split(versionStr, "-")
	verPart := parts[len(parts)-1] // 取最后一段
	majorStr := strings.Split(verPart, ".")[0]
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return false
	}
	return major < 20
}

// InstallForge 安装 Forge（完全按照 PCL 逻辑）
func (a *App) InstallForge(mcVersion string, forgeVersion string) error {
	a.writeLog("========== 开始安装 Forge: MC=%s, Forge=%s ==========", mcVersion, forgeVersion)

	// forgeVersion 可能是 "47.3.0" 或完整版 "1.20.1-47.3.0"
	fullVersion := forgeVersion
	if !strings.Contains(forgeVersion, mcVersion) {
		fullVersion = mcVersion + "-" + forgeVersion
	}
	a.writeLog("完整版本号: %s", fullVersion)

	mcDir := a.GetMinecraftDir()
	a.writeLog(".minecraft 目录: %s", mcDir)

	// 1. 下载 Forge installer
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	// Forge 阶段划分：安装器下载 0-30%，支持库 35-90%，运行安装器 90-100%
	a.setProgressScale(0, 30)

	installerPath := filepath.Join(tempDir, fmt.Sprintf("forge-%s-installer.jar", fullVersion))

	a.emitProgress("downloading", "下载 Forge 安装器", 0, 0)

	// BMCLAPI 镜像下载
	downloadURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/maven/net/minecraftforge/forge/%s/forge-%s-installer.jar",
		fullVersion, fullVersion,
	)
	a.writeLog("下载 URL: %s", downloadURL)

	// 删除旧的安装器文件（避免下载跳过损坏文件）
	os.Remove(installerPath)

	if err := a.downloadFile(downloadURL, installerPath, true); err != nil {
		a.writeLog("下载 Forge 安装器失败: %v", err)
		return fmt.Errorf("下载 Forge 安装器失败: %v", err)
	}

	// 检查下载的文件大小
	if info, err := os.Stat(installerPath); err == nil {
		a.writeLog("安装器文件大小: %d 字节", info.Size())
	} else {
		a.writeLog("无法获取安装器文件信息: %v", err)
	}

	// 2. 判断是新版还是旧版
	isOld := isOldForge(fullVersion)
	a.writeLog("是否为旧版 Forge (<20): %v (isOldForge 判断)", isOld)

	if isOld {
		// 旧版 Forge（方式 B）：直接解压 installer jar，不需要运行安装器
		a.setProgressScale(35, 95)
		a.emitProgress("downloading", "安装旧版 Forge", 0, 0)
		return a.installOldForge(installerPath, mcDir, mcVersion)
	}

	// 3. 新版 Forge（方式 A）：先分析支持库，再运行 bangbang93 ForgeInstaller
	a.setProgressScale(35, 90)
	a.emitProgress("downloading", "分析 Forge 支持库", 0, 0)

	// 3.1 解压 installer 获取支持库列表并下载
	if err := a.downloadForgeLibraries(installerPath, mcDir, mcVersion); err != nil {
		a.writeLog("下载 Forge 支持库失败（将继续尝试安装）: %v", err)
	}

	// 3.2 确保 launcher_profiles.json 存在
	a.ensureLauncherProfiles(mcDir)

	// 3.3 记录当前版本文件夹列表（在运行安装器之前）
	oldVersions := a.getVersionFolderList(mcDir)

	// 3.4 运行 bangbang93 ForgeInstaller
	a.setProgressScale(90, 100)
	a.emitProgress("downloading", "运行 Forge 安装器", 0, 0)

	err := a.runForgeInstaller(installerPath, mcDir)
	if err != nil {
		return err
	}

	// 3.5 查找安装器创建的版本文件夹
	newVersionFolder := a.findNewVersionFolder(mcDir, oldVersions, mcVersion, "forge")
	if newVersionFolder == "" {
		return fmt.Errorf("Forge 安装器运行完成但未找到版本文件夹")
	}

	// 3.6 验证安装
	if !a.validateVersionInstallation(newVersionFolder) {
		os.RemoveAll(newVersionFolder)
		return fmt.Errorf("Forge 安装验证失败：版本 JSON 无效")
	}

	fmt.Printf("Forge 安装成功: %s\n", filepath.Base(newVersionFolder))

	// 3.7 清理安装器
	os.Remove(installerPath)

	return nil
}

// installOldForge 旧版 Forge 安装（方式 B，不需要运行安装器）
func (a *App) installOldForge(installerPath string, mcDir string, mcVersion string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return fmt.Errorf("打开 Forge 安装器失败: %v", err)
	}
	defer r.Close()

	// 读取 install_profile.json
	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("读取 install_profile.json 失败: %v", err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
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

	// 确定版本 ID（从 install_profile.json 中获取）
	targetVersion := ""
	if id, ok := installProfile["id"].(string); ok && id != "" {
		targetVersion = id
	}
	if targetVersion == "" {
		targetVersion = mcVersion + "-forge-unknown"
	}

	versionFolder := filepath.Join(mcDir, "versions", targetVersion)

	// 创建版本文件夹
	if err := os.MkdirAll(versionFolder, 0755); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}

	if installProfile["install"] == nil {
		// 中版：Legacy 方式 1
		// 从安装器中提取版本 JSON
		jsonPath, _ := installProfile["json"].(string)
		if jsonPath == "" {
			return fmt.Errorf("install_profile.json 中缺少 json 字段")
		}
		jsonPath = strings.TrimPrefix(jsonPath, "/")

		var versionJSONData []byte
		for _, f := range r.File {
			if f.Name == jsonPath {
				rc, err := f.Open()
				if err != nil {
					return fmt.Errorf("读取版本 JSON 失败: %v", err)
				}
				versionJSONData, _ = io.ReadAll(rc)
				rc.Close()
				break
			}
		}

		if versionJSONData == nil {
			return fmt.Errorf("安装器中未找到 %s", jsonPath)
		}

		// 设置版本 ID 和 inheritsFrom
		var versionJSON map[string]interface{}
		if err := json.Unmarshal(versionJSONData, &versionJSON); err != nil {
			return fmt.Errorf("解析版本 JSON 失败: %v", err)
		}
		versionJSON["id"] = targetVersion
		if versionJSON["inheritsFrom"] == nil {
			versionJSON["inheritsFrom"] = mcVersion
		}

		// 保存版本 JSON
		outputData, _ := json.MarshalIndent(versionJSON, "", "  ")
		jsonFilePath := filepath.Join(versionFolder, targetVersion+".json")
		if err := os.WriteFile(jsonFilePath, outputData, 0644); err != nil {
			return fmt.Errorf("保存版本 JSON 失败: %v", err)
		}

		// 解压 maven 文件到 libraries 目录
		r.Close()
		if err := a.extractMavenFiles(installerPath, mcDir); err != nil {
			fmt.Printf("解压 maven 文件失败（可能不影响启动）: %v\n", err)
		}
	} else {
		// 旧版：Legacy 方式 2
		installInfo := installProfile["install"].(map[string]interface{})
		filePath, _ := installInfo["filePath"].(string)
		pathStr, _ := installInfo["path"].(string)

		// 提取 Jar 文件到 libraries
		if pathStr != "" && filePath != "" {
			libPath := filepath.Join(mcDir, "libraries", strings.ReplaceAll(pathStr, "/", string(os.PathSeparator)))
			os.MkdirAll(filepath.Dir(libPath), 0755)

			for _, f := range r.File {
				if f.Name == filePath {
					rc, err := f.Open()
					if err != nil {
						break
					}
					data, _ := io.ReadAll(rc)
					rc.Close()
					os.WriteFile(libPath, data, 0644)
					break
				}
			}
		}

		// 提取版本 JSON
		versionInfo := installProfile["versionInfo"]
		if versionInfo != nil {
			vi := versionInfo.(map[string]interface{})
			vi["id"] = targetVersion
			if vi["inheritsFrom"] == nil {
				vi["inheritsFrom"] = mcVersion
			}
			outputData, _ := json.MarshalIndent(vi, "", "  ")
			jsonFilePath := filepath.Join(versionFolder, targetVersion+".json")
			os.WriteFile(jsonFilePath, outputData, 0644)
		}
	}

	// 验证安装
	if !a.validateVersionInstallation(versionFolder) {
		os.RemoveAll(versionFolder)
		return fmt.Errorf("旧版 Forge 安装验证失败")
	}

	fmt.Printf("旧版 Forge 安装成功: %s\n", targetVersion)

	// 清理安装器
	os.Remove(installerPath)

	return nil
}

// extractMavenFiles 从安装器中解压 maven 文件到 libraries 目录
func (a *App) extractMavenFiles(installerPath string, mcDir string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return err
	}
	defer r.Close()

	libsDir := filepath.Join(mcDir, "libraries")

	for _, f := range r.File {
		// 只解压 maven/ 目录下的文件
		if strings.HasPrefix(f.Name, "maven/") && !f.FileInfo().IsDir() {
			relPath := strings.TrimPrefix(f.Name, "maven/")
			destPath := filepath.Join(libsDir, relPath)

			os.MkdirAll(filepath.Dir(destPath), 0755)

			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			os.WriteFile(destPath, data, 0644)
		}
	}

	return nil
}

// downloadForgeLibraries 分析并下载 Forge 支持库文件
func (a *App) downloadForgeLibraries(installerPath string, mcDir string, mcVersion string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return fmt.Errorf("打开安装器失败: %v", err)
	}
	defer r.Close()

	// 读取 install_profile.json 和 version.json
	var profileData, versionData map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			json.Unmarshal(data, &profileData)
		}
		if f.Name == "version.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			json.Unmarshal(data, &versionData)
		}
	}

	if profileData == nil {
		return fmt.Errorf("未找到 install_profile.json")
	}

	// 合并两个 JSON 的 libraries
	var allLibs []interface{}
	if libs, ok := profileData["libraries"].([]interface{}); ok {
		allLibs = append(allLibs, libs...)
	}
	if versionData != nil {
		if libs, ok := versionData["libraries"].([]interface{}); ok {
			allLibs = append(allLibs, libs...)
		}
	}

	// 下载每个支持库（先收集任务再带计数进度下载）
	libsDir := filepath.Join(mcDir, "libraries")
	type libDlTask struct {
		url  string
		path string
		name string
	}
	var libTasks []libDlTask
	for _, lib := range allLibs {
		libMap, ok := lib.(map[string]interface{})
		if !ok {
			continue
		}

		// 获取下载信息
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

		// 替换为 BMCLAPI 镜像
		url = strings.Replace(url, "https://maven.minecraftforge.net/", "https://bmclapi2.bangbang93.com/maven/", 1)
		url = strings.Replace(url, "https://maven.neoforged.net/releases/", "https://bmclapi2.bangbang93.com/maven/", 1)
		url = strings.Replace(url, "https://maven.fabricmc.net/", "https://bmclapi2.bangbang93.com/maven/", 1)

		destPath := filepath.Join(libsDir, path)
		if _, err := os.Stat(destPath); err == nil {
			continue // 已存在
		}

		libTasks = append(libTasks, libDlTask{url: url, path: destPath, name: filepath.Base(path)})
	}

	for i, task := range libTasks {
		a.emitProgress("downloading", fmt.Sprintf("支持库 %d/%d: %s", i+1, len(libTasks), task.name), int64(i+1), int64(len(libTasks)))
		if err := a.downloadFile(task.url, task.path, false); err != nil {
			fmt.Printf("下载支持库失败 %s: %v\n", task.name, err)
		}
	}

	// === 新版 Forge 需要 Mappings 文件（参考 PCL 的 DlClientFix） ===
	// install_profile.json 中的 data.MOJMAPS 字段引用了原版 MC 的 client_mappings
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
// 使用 CMD 命令（Invoke-WebRequest）下载文件
func (a *App) ensureForgeMappings(installerPath string, mcDir string) {
	a.writeLog("===== 开始检查 Forge Mappings 文件 =====")

	// 1. 从 install_profile.json 获取配置
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
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()

			json.Unmarshal(data, &installProfile)

			// 获取 mcVersion - 新版 Forge 中 minecraft 是字符串格式 "1.19.2"
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

	// 2. 检查是否需要 MOJMAPS
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

	// 解析 MOJMAPS.client: [net.minecraft:client:1.19.2-20220805.130853:mappings@txt]
	clientValue = strings.Trim(clientValue, "[]")
	atIndex := strings.Index(clientValue, "@")
	if atIndex == -1 {
		a.writeLog("MOJMAPS.client 格式错误（跳过 Mappings 检查）")
		return
	}

	originalName := clientValue[:atIndex]
	extension := clientValue[atIndex+1:]

	parts := strings.Split(originalName, ":")
	if len(parts) < 3 {
		a.writeLog("MOJMAPS.client Maven 格式错误（跳过 Mappings 检查）")
		return
	}

	groupPath := strings.Replace(parts[0], ".", "/", -1)
	artifact := parts[1]
	versionPart := parts[2]

	targetPath := filepath.Join(mcDir, "libraries", groupPath, artifact, versionPart,
		fmt.Sprintf("%s-%s-mappings.%s", artifact, versionPart, extension))

	a.writeLog("目标路径: %s", targetPath)

	// 检查是否已存在
	if _, err := os.Stat(targetPath); err == nil {
		a.writeLog("Mappings 文件已存在: %s", targetPath)
		return
	}

	// 3. 从原版版本 JSON 获取 client_mappings URL
	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		a.writeLog("无法读取原版版本 JSON: %v", err)
		return
	}

	var rawJSON map[string]interface{}
	json.Unmarshal(jsonData, &rawJSON)

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

	// 替换为 BMCLAPI 镜像
	mappingsURL = strings.Replace(mappingsURL, "https://piston-data.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
	mappingsURL = strings.Replace(mappingsURL, "https://launcher.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)

	a.writeLog("使用 CMD 命令下载 Mappings 文件...")
	a.writeLog("下载 URL: %s", mappingsURL)
	a.writeLog("保存到: %s", targetPath)

	// 4. 创建目标目录
	os.MkdirAll(filepath.Dir(targetPath), 0755)

	// 5. 使用 PowerShell Invoke-WebRequest 下载文件（带 User-Agent 避免被拦截）
	a.writeLog("执行下载命令...")
	downloadCmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $headers = @{'User-Agent'='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1'}; Invoke-WebRequest -Uri '%s' -OutFile '%s' -UseBasicParsing -Headers $headers",
			mappingsURL, targetPath))
	downloadCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := downloadCmd.CombinedOutput()

	if err != nil {
		a.writeLog("CMD 下载失败: %v, 输出: %s", err, string(output))
		return
	}

	// 6. 验证文件是否存在且不为空
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

// downloadForgeMappings 下载 Forge 新版所需的 client_mappings 文件（保留旧函数以保持兼容性）
// Forge 安装器期望的路径格式: libraries/net/minecraft/client/{mcpVersion}/client-{mcpVersion}-mappings.txt
func (a *App) downloadForgeMappings(mcDir string, mcVersion string, installerPath string) {
	// 1. 从 install_profile.json 获取 MOJMAPS 配置
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		fmt.Printf("无法打开安装器（跳过 Mappings 下载）: %v\n", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			json.Unmarshal(data, &installProfile)
			break
		}
	}

	if installProfile == nil {
		fmt.Printf("未找到 install_profile.json（跳过 Mappings 下载）\n")
		return
	}

	// 2. 获取 MOJMAPS 数据（包含 mcpVersion）
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

	// 3. 构建目标路径
	// Forge 安装器期望的路径: libraries/net/minecraft/client/{mcpVersion}/client-{mcpVersion}-mappings.txt
	targetPath := filepath.Join(mcDir, "libraries", "net", "minecraft", "client", mcpVersion, fmt.Sprintf("client-%s-mappings.txt", mcpVersion))

	// 检查是否已存在
	if _, err := os.Stat(targetPath); err == nil {
		fmt.Printf("Mappings 文件已存在: %s\n", targetPath)
		return
	}

	// 4. 尝试从原版版本 JSON 获取 client_mappings 下载信息
	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		fmt.Printf("无法读取原版版本 JSON（跳过 Mappings 下载）: %v\n", err)
		return
	}

	var rawJSON map[string]interface{}
	if err := json.Unmarshal(jsonData, &rawJSON); err != nil {
		fmt.Printf("解析原版版本 JSON 失败（跳过 Mappings 下载）: %v\n", err)
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

	// 5. 替换为 BMCLAPI 镜像
	mappingsURL = strings.Replace(mappingsURL, "https://piston-data.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
	mappingsURL = strings.Replace(mappingsURL, "https://launcher.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)

	// 6. 创建目标目录
	os.MkdirAll(filepath.Dir(targetPath), 0755)

	// 7. 下载文件（先下载为临时文件，然后重命名）
	tempPath := targetPath + ".tmp"
	fmt.Printf("下载 Forge Mappings (%s): %s\n", mcpVersion, mappingsURL)
	if err := a.downloadFile(mappingsURL, tempPath, false); err != nil {
		// 如果临时文件已存在，删除它
		os.Remove(tempPath)
		fmt.Printf("下载 Mappings 失败: %v\n", err)
		return
	}

	// 8. 重命名为 Forge 安装器期望的名称
	if err := os.Rename(tempPath, targetPath); err != nil {
		os.Remove(tempPath)
		fmt.Printf("重命名 Mappings 文件失败: %v\n", err)
		return
	}

	fmt.Printf("Mappings 下载成功: %s\n", targetPath)
}

// ensureLauncherProfiles 确保 launcher_profiles.json 存在（Forge 安装器需要）
func (a *App) ensureLauncherProfiles(mcDir string) {
	profilesPath := filepath.Join(mcDir, "launcher_profiles.json")
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		profiles := map[string]interface{}{
			"profiles": map[string]interface{}{},
		}
		data, _ := json.MarshalIndent(profiles, "", "  ")
		os.WriteFile(profilesPath, data, 0644)
	}
}

// getVersionFolderList 获取当前版本文件夹列表
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

// runForgeInstaller 运行 bangbang93 ForgeInstaller（完全按照 PCL 的命令行）
func (a *App) runForgeInstaller(installerPath string, mcDir string) error {
	a.writeLog("===== 开始运行 ForgeInstaller =====")

	// 0. 确保新版 Forge 需要的 Mappings 文件存在（参考 PCL 的 DlClientFix）
	a.ensureForgeMappings(installerPath, mcDir)

	// 1. 提取 bangbang93 ForgeInstaller
	bbInstallerPath, err := a.extractForgeInstaller()
	if err != nil {
		a.writeLog("提取 ForgeInstaller 失败: %v", err)
		return err
	}
	a.writeLog("ForgeInstaller 路径: %s", bbInstallerPath)
	a.writeLog("Forge 安装器路径: %s", installerPath)

	// 2. 选择 Java
	javaEntry, err := a.selectJavaForInstaller()
	if err != nil {
		a.writeLog("选择 Java 失败: %v", err)
		return fmt.Errorf("选择 Java 失败: %v", err)
	}
	a.writeLog("使用 Java: %s (版本: %s, 主版本: %d)", javaEntry.Path, javaEntry.Version, javaEntry.MajorVer)

	// 3. 构造命令行参数（完全按照 PCL 的方式）
	classpath := bbInstallerPath + ";" + installerPath

	args := []string{}
	if javaEntry.MajorVer >= 9 {
		args = append(args, "--add-exports", "cpw.mods.bootstraplauncher/cpw.mods.bootstraplauncher=ALL-UNNAMED")
	}
	args = append(args, "-cp", classpath, "com.bangbang93.ForgeInstaller", mcDir)

	a.writeLog("完整命令: %s %s", javaEntry.Path, strings.Join(args, " "))

	// 4. 启动进程
	cmd := exec.Command(javaEntry.Path, args...)
	cmd.Dir = mcDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	// 5. 使用 CombinedOutput 捕获完整输出
	output, runErr := cmd.CombinedOutput()
	outputStr := string(output)

	// 写入完整输出到日志
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

	// 6. 检查输出中是否有 "true"（bangbang93 安装器成功标志，只看最后4行）
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

	// 严格按照用户要求：未检测到 "true" 标志即为安装失败，即使版本文件夹存在也不例外
	a.writeLog("未检测到安装器成功标志 'true'，安装失败")

	// 8. 返回详细错误信息
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

// findNewVersionFolder 查找安装器新创建的版本文件夹
