package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

)

func (a *App) ViewFullLog() {
	path := a.launchLogPath
	if path == "" {
		path = filepath.Join(a.GetMinecraftDir(), "qgl_install.log")
	}
	// 文件不存在时先写出当前日志内容，保证记事本能打开
	if _, err := os.Stat(path); err != nil {
		os.MkdirAll(filepath.Dir(path), 0755)
		os.WriteFile(path, []byte(a.GetFullLog()), 0644)
	}
	exec.Command("notepad.exe", path).Start()
}

// ===== 嵌入 bangbang93 ForgeInstaller =====

//go:embed resources/forge-installer.jar
var forgeInstallerJar []byte

// ===== 模组加载器相关结构体 =====

// LoaderInfo 模组加载器信息
type LoaderInfo struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Version      string `json:"version"`
	MCVersion    string `json:"mcVersion"`
	DownloadURL  string `json:"downloadUrl"`
	IsInstalled  bool   `json:"isInstalled"`
	Stable       bool   `json:"stable"`
	Category     string `json:"category"`     // installer, universal, client (Forge)
	ForgeVersion string `json:"forgeVersion"` // Forge 完整版本名如 1.20.1-47.3.0
	IsPreview    bool   `json:"isPreview"`    // OptiFine 是否为预览版
	Patch        string `json:"patch"`        // OptiFine patch 版本号
	OptiFineType string `json:"optifineType"` // OptiFine 类型如 HD_U
}

// BMCLAPI Forge 版本条目
type BMCLAPIForgeEntry struct {
	Branch   string `json:"branch"`
	Modified string `json:"modified"`
	Version  string `json:"version"`
	Files    []struct {
		Category string `json:"category"`
		Format   string `json:"format"`
		Hash     string `json:"hash"`
		ID       int    `json:"id"`
		Size     int64  `json:"size"`
	} `json:"files"`
}

// BMCLAPI OptiFine 版本条目
type BMCLAPIOptiFineEntry struct {
	MCVersion string `json:"mcversion"`
	Type      string `json:"type"`
	Patch     string `json:"patch"`
	Filename  string `json:"filename"`
	Forge     string `json:"forge"`
}

// Fabric 加载器版本
type FabricLoaderVersion struct {
	Separator string `json:"separator"`
	Build     int    `json:"build"`
	Version   string `json:"version"`
	Maven     string `json:"maven"`
	Stable    bool   `json:"stable"`
}

// ===== Forge 版本获取（使用 BMCLAPI） =====

// GetForgeVersions 获取 Forge 版本列表
func (a *App) GetForgeVersions(mcVersion string) ([]LoaderInfo, error) {
	apiURL := fmt.Sprintf("https://bmclapi2.bangbang93.com/forge/minecraft/%s", mcVersion)

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Forge 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Forge 版本失败: HTTP %d", resp.StatusCode)
	}

	var entries []BMCLAPIForgeEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("解析 Forge 版本失败: %v", err)
	}

	// 获取推荐版本
	recommendedVersion := ""
	promosResp, err := http.Get("https://bmclapi2.bangbang93.com/forge/promos")
	if err == nil && promosResp.StatusCode == http.StatusOK {
		var promos map[string]string
		if json.NewDecoder(promosResp.Body).Decode(&promos) == nil {
			recommendedVersion = promos[mcVersion+"-recommended"]
		}
		promosResp.Body.Close()
	}

	loaders := []LoaderInfo{}
	for _, entry := range entries {
		// 选择最佳文件类型：installer.jar > universal.zip
		var bestFile *struct {
			Category string `json:"category"`
			Format   string `json:"format"`
			Hash     string `json:"hash"`
			ID       int    `json:"id"`
			Size     int64  `json:"size"`
		}

		for i := range entry.Files {
			f := &entry.Files[i]
			if f.Category == "installer" && f.Format == "jar" {
				bestFile = f
				break
			}
			if f.Category == "universal" && bestFile == nil {
				bestFile = f
			}
		}

		if bestFile == nil && len(entry.Files) > 0 {
			bestFile = &entry.Files[0]
		}

		forgeVersion := mcVersion + "-" + entry.Version
		if entry.Branch != "" {
			forgeVersion += "-" + entry.Branch
		}

		category := "installer"
		if bestFile != nil {
			category = bestFile.Category
		}

		// 构建下载 URL
		ext := "jar"
		if category == "universal" || category == "client" {
			ext = "zip"
		}
		downloadURL := fmt.Sprintf(
			"https://bmclapi2.bangbang93.com/maven/net/minecraftforge/forge/%s/forge-%s-%s.%s",
			forgeVersion, forgeVersion, category, ext,
		)

		isRecommended := entry.Version == recommendedVersion

		loaders = append(loaders, LoaderInfo{
			Name:         "forge",
			DisplayName:  "Forge",
			Version:      entry.Version,
			MCVersion:    mcVersion,
			DownloadURL:  downloadURL,
			Stable:       isRecommended,
			Category:     category,
			ForgeVersion: forgeVersion,
		})
	}

	return loaders, nil
}

// ===== Fabric 版本获取 =====

// GetFabricVersions 获取 Fabric 版本列表
func (a *App) GetFabricVersions(mcVersion string) ([]LoaderInfo, error) {
	// 参考 PCL：先获取完整版本列表，检查 MC 版本是否在 game 数组中
	// 优先使用 BMCLAPI 镜像，失败回退官方源
	fabricMetaURL := "https://bmclapi2.bangbang93.com/fabric-meta/v2/versions"

	resp, err := http.Get(fabricMetaURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		// 回退到官方源
		resp, err = http.Get("https://meta.fabricmc.net/v2/versions")
		if err != nil {
			return nil, fmt.Errorf("获取 Fabric 版本失败: %v", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Fabric 版本失败: HTTP %d", resp.StatusCode)
	}

	var fabricMeta struct {
		Game     []struct {
			Version string `json:"version"`
			Stable bool   `json:"stable"`
		} `json:"game"`
		Loader []FabricLoaderVersion `json:"loader"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fabricMeta); err != nil {
		return nil, fmt.Errorf("解析 Fabric 版本失败: %v", err)
	}

	// 检查 MC 版本是否在 game 数组中（参考 PCL LoadFabricGetError）
	mcVersionNormalized := mcVersion
	if mcVersionNormalized == "infinite" {
		mcVersionNormalized = "infinite"
	}
	supported := false
	for _, g := range fabricMeta.Game {
		if g.Version == mcVersionNormalized {
			supported = true
			break
		}
	}
	// 如果不支持，返回空列表（参考 PCL 显示"不可用"）
	if !supported {
		return []LoaderInfo{}, nil
	}

	loaders := []LoaderInfo{}
	for _, lv := range fabricMeta.Loader {
		loaders = append(loaders, LoaderInfo{
			Name:        "fabric",
			DisplayName: "Fabric",
			Version:     lv.Version,
			MCVersion:   mcVersion,
			DownloadURL: "",
			Stable:      lv.Stable,
		})
	}

	return loaders, nil
}

// ===== NeoForge 版本获取 =====

// GetNeoForgeVersions 获取 NeoForge 版本列表（参考 PCL DlNeoForgeList）
