package main

import (
	_ "embed"
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
