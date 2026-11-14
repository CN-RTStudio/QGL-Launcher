package main

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

)



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
