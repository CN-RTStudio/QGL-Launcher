package main

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

)

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
