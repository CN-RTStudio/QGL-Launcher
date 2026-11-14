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

func (a *App) installModpack(item *DownloadItem) error {
	mcDir := a.GetMinecraftDir()

	// 1. 下载整合包文件到临时目录
	tmpDir := filepath.Join(os.TempDir(), "qgl-modpack")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mrpackPath := filepath.Join(tmpDir, "modpack.mrpack")
	a.emitProgress("downloading", item.CustomName, 0, 0)
	// 整合包阶段划分：压缩包 0-15%，游戏 15-55%，加载器 55-80%，Mod 80-97%，覆写 97-100%
	a.setProgressScale(0, 15)

	// 多线程分段下载（先镜像源，失败回退官方源）
	if err := a.downloadFileMultiThread(mirrorModURL(item.URL), mrpackPath, 8); err != nil {
		a.writeLog("整合包镜像下载失败 [%s]: %v，尝试官方源", item.URL, err)
		os.Remove(mrpackPath)
		if err2 := a.downloadFileMultiThread(item.URL, mrpackPath, 8); err2 != nil {
			return fmt.Errorf("下载整合包失败: %v", err2)
		}
	}

	// 2. 打开 zip 并解析 modrinth.index.json
	r, err := zip.OpenReader(mrpackPath)
	if err != nil {
		return fmt.Errorf("打开整合包失败: %v", err)
	}
	defer r.Close()

	var manifestEntry *zip.File
	for _, f := range r.File {
		if f.Name == "modrinth.index.json" {
			manifestEntry = f
			break
		}
	}
	if manifestEntry == nil {
		return fmt.Errorf("整合包中未找到 modrinth.index.json")
	}

	rc, err := manifestEntry.Open()
	if err != nil {
		return fmt.Errorf("读取 manifest 失败: %v", err)
	}
	manifestData, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return fmt.Errorf("读取 manifest 数据失败: %v", err)
	}

	var manifest ModrinthModpackManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("解析 manifest 失败: %v", err)
	}

	// 3. 从 dependencies 获取游戏版本和 loader
	mcVersion := manifest.Dependencies["minecraft"]
	fabricVersion := manifest.Dependencies["fabric-loader"]
	forgeVersion := manifest.Dependencies["forge"]
	neoforgeVersion := manifest.Dependencies["neoforge"]
	quiltVersion := manifest.Dependencies["quilt-loader"]

	if mcVersion == "" {
		return fmt.Errorf("整合包未指定 Minecraft 版本")
	}

	// 4. 下载游戏版本（使用现有 DownloadVersion 逻辑 + 进度）
	// 注意：传 mcVersion 作为 customName，因为 Install* 函数期望第一个参数是 MC 版本号
	a.setProgressScale(15, 55)
	a.emitProgress("downloading", "下载游戏 "+mcVersion, 0, 0)
	versionURL := ""
	mcManifest, err2 := a.GetVersionManifest()
	if err2 == nil {
		for _, v := range mcManifest {
			if v.ID == mcVersion {
				versionURL = v.URL
				break
			}
		}
	}
	if versionURL == "" {
		return fmt.Errorf("未找到 Minecraft %s 的下载地址", mcVersion)
	}
	if err := a.DownloadVersion(mcVersion, versionURL, mcVersion); err != nil {
		return fmt.Errorf("下载游戏版本失败: %v", err)
	}

	// 5. 安装 loader（传 mcVersion，不是 versionName）
	// 安装前记录 versions 目录，安装后找到 loader 创建的新版本文件夹
	a.setProgressScale(55, 80)
	versionsDir := filepath.Join(mcDir, "versions")
	oldFolders := listVersionFolders(versionsDir)

	if fabricVersion != "" {
		a.emitProgress("downloading", "安装 Fabric "+fabricVersion, 0, 0)
		if err := a.InstallFabric(mcVersion, fabricVersion); err != nil {
			return fmt.Errorf("安装 Fabric 失败: %v", err)
		}
	} else if forgeVersion != "" {
		a.emitProgress("downloading", "安装 Forge "+forgeVersion, 0, 0)
		if err := a.InstallForge(mcVersion, forgeVersion); err != nil {
			return fmt.Errorf("安装 Forge 失败: %v", err)
		}
	} else if neoforgeVersion != "" {
		a.emitProgress("downloading", "安装 NeoForge "+neoforgeVersion, 0, 0)
		if err := a.InstallNeoForge(mcVersion, neoforgeVersion); err != nil {
			return fmt.Errorf("安装 NeoForge 失败: %v", err)
		}
	} else if quiltVersion != "" {
		return fmt.Errorf("Quilt 加载器暂不支持，请手动安装")
	}

	// 找到 loader 创建的新版本文件夹（不重命名，直接使用）
	newFolders := listVersionFolders(versionsDir)
	versionDir := ""
	for _, f := range newFolders {
		if !containsStr(oldFolders, f) {
			versionDir = filepath.Join(versionsDir, f)
			break
		}
	}
	// 如果没找到新文件夹，回退到 mcVersion 目录
	if versionDir == "" {
		versionDir = filepath.Join(versionsDir, mcVersion)
	}

	// 6. 下载所有 mod 文件（使用现有 downloadFile 逻辑 + 进度）
	modsDir := filepath.Join(versionDir, "mods")
	if err := os.MkdirAll(modsDir, 0755); err != nil {
		return fmt.Errorf("创建 mods 目录失败: %v", err)
	}

	// Mod 阶段占 80-97%，进度条按文件数推进，即使单个文件无 Content-Length 也不会卡 0%
	a.setProgressScale(80, 97)
	totalFiles := len(manifest.Files)
	for i, mf := range manifest.Files {
		// 跳过非 mods 目录的文件（如 resourcepacks、shaderpacks 等也一并处理）
		destPath, pathOK := archiveEntryPathInside(versionDir, mf.Path)
		if !pathOK {
			continue
		}
		destDir := filepath.Dir(destPath)
		if err := os.MkdirAll(destDir, 0755); err != nil {
			continue
		}

		// 如果文件已存在则跳过
		if _, err := os.Stat(destPath); err == nil {
			continue
		}

		fileName := filepath.Base(mf.Path)
		// 进度按第 i 个文件推进（而非单个文件字节），总百分比稳定可见
		a.emitProgress("downloading", fmt.Sprintf("Mod %d/%d: %s", i+1, totalFiles, fileName), int64(i+1), int64(totalFiles))

		// 尝试所有下载链接（先镜像源，失败回退官方源）
		downloaded := false
		for _, dlURL := range mf.Downloads {
			// 先尝试镜像源
			if err := a.downloadFile(mirrorModURL(dlURL), destPath, false); err == nil {
				downloaded = true
				break
			}
			// 镜像失败，回退到官方源
			if err := a.downloadFile(dlURL, destPath, false); err == nil {
				downloaded = true
				break
			}
		}
		if !downloaded {
			fmt.Printf("下载整合包文件失败(跳过): %s\n", mf.Path)
			continue
		}
		if err := verifyModrinthFile(destPath, mf.Hashes); err != nil {
			os.Remove(destPath)
			fmt.Printf("整合包文件校验失败(已删除): %s %v\n", mf.Path, err)
		}
	}

	// 7. 解压 overrides 目录到版本目录
	a.setProgressScale(97, 100)
	a.emitProgress("downloading", "解压覆写文件", 0, 0)
	for _, f := range r.File {
		// 处理 overrides/ 和 client-overrides/
		var relPath string
		if strings.HasPrefix(f.Name, "overrides/") {
			relPath = strings.TrimPrefix(f.Name, "overrides/")
		} else if strings.HasPrefix(f.Name, "client-overrides/") {
			relPath = strings.TrimPrefix(f.Name, "client-overrides/")
		} else {
			continue
		}
		if relPath == "" {
			continue
		}

		destPath, ok := archiveEntryPathInside(versionDir, relPath)
		if !ok {
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(destPath), 0755)

		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}

	// 8. 写入 QGL/config.json 标记为整合包
	configDir := filepath.Join(versionDir, "QGL")
	if err := os.MkdirAll(configDir, 0755); err == nil {
		loaderType := ""
		if fabricVersion != "" {
			loaderType = "fabric"
		} else if forgeVersion != "" {
			loaderType = "forge"
		} else if neoforgeVersion != "" {
			loaderType = "neoforge"
		}
		config := map[string]string{
			"type":    "modpack",
			"name":    item.CustomName,
			"version": mcVersion,
			"loader":  loaderType,
		}
		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0644)
	}

	return nil
}

// listVersionFolders 列出 versions 目录下的所有子文件夹名
