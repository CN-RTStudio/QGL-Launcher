package main

import (
	"path/filepath"
	"strings"
)

// readQGLVersionConfig 有界读取某个版本目录下启动器自写的 QGL/config.json。
// 历史上 readVersionInfo / scanVersionFolder 各自 os.ReadFile+Unmarshal 一份，
// 既重复又没有体积上限；统一收口到 readLocalJSONBounded。
func readQGLVersionConfig(versionFolder string) (map[string]string, bool) {
	configPath := filepath.Join(versionFolder, "QGL", "config.json")
	var config map[string]string
	if err := readLocalJSONBounded(configPath, &config, 0, "版本 QGL 配置"); err != nil {
		return nil, false
	}
	return config, true
}

func (a *App) readVersionInfo(versionFolder string, folderName string) InstalledVersionInfo {
	if config, ok := readQGLVersionConfig(versionFolder); ok {
		return InstalledVersionInfo{
			FolderName: folderName, Name: config["name"],
			Version: config["version"], Loader: config["loader"], Type: config["type"],
		}
	}
	return InstalledVersionInfo{FolderName: folderName, Version: folderName, Type: "game"}
}

func (a *App) scanVersionFolder(versionFolder string, folderName string) InstalledVersionInfo {
	if config, ok := readQGLVersionConfig(versionFolder); ok {
		return InstalledVersionInfo{
			FolderName: folderName, Name: config["name"],
			Version: config["version"], Loader: config["loader"], Type: config["type"],
		}
	}
	versionJSON, err := a.resolveVersionJSON(folderName)
	if err != nil {
		return InstalledVersionInfo{FolderName: folderName, Version: folderName, Type: "game"}
	}
	jsonPath := filepath.Join(versionFolder, folderName+".json")
	if !inspectRegularFile(jsonPath).trustable() {
		jsonFiles, _ := filepath.Glob(filepath.Join(versionFolder, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		}
	}
	jsonText, _ := readBoundedFile(jsonPath, maxMetadataJSONBytes)
	loader := ""
	if strings.Contains(string(jsonText), "net.fabricmc:fabric-loader") {
		loader = "fabric"
	} else if strings.Contains(string(jsonText), "org.quiltmc:quilt-loader") {
		loader = "quilt"
	} else if strings.Contains(string(jsonText), "net.neoforged") {
		loader = "neoforge"
	} else if strings.Contains(string(jsonText), "minecraftforge") && !strings.Contains(string(jsonText), "net.neoforged") {
		loader = "forge"
	}
	gameVersion := versionJSON.InheritsFrom
	if gameVersion == "" {
		gameVersion = versionJSON.ID
	}
	versionType := "game"
	if loader != "" {
		versionType = "loader"
	}
	info := InstalledVersionInfo{FolderName: folderName, Version: gameVersion, Loader: loader, Type: versionType}
	configDir := filepath.Join(versionFolder, "QGL")
	if err := ensurePrivateDir(configDir); err == nil {
		config := map[string]string{"type": versionType, "name": "", "version": gameVersion, "loader": loader}
		// 版本标记 config.json 走有界原子私有写，并对已存在的宽权限目录统一收权到 0700。
		_ = writePrivateJSON(filepath.Join(configDir, "config.json"), config)
	}
	return info
}
