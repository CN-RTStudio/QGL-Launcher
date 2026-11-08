package main

import (
	"archive/zip"
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
