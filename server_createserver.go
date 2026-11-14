package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) CreateServer(name, version string, port, maxMem, minMem int, onlineMode bool, customDir string) error {
	serverDir := a.GetServerDir()
	var dir string
	if customDir != "" {
		dir = customDir
	} else {
		dir = filepath.Join(serverDir, name)
	}

	// 创建目录
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建服务器目录失败: %v", err)
	}

	// 保存 QGL 配置
	qglDir := filepath.Join(dir, "QGL")
	if err := os.MkdirAll(qglDir, 0755); err != nil {
		return fmt.Errorf("创建 QGL 配置目录失败: %v", err)
	}

	cfg := ServerConfig{
		Name:       name,
		Version:    version,
		Port:       port,
		MaxMemory:  maxMem,
		MinMemory:  minMem,
		OnlineMode: onlineMode,
		ServerDir:  dir,
	}

	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(qglDir, "config.json"), cfgData, 0644); err != nil {
		return fmt.Errorf("保存配置失败: %v", err)
	}

	// 下载服务器 JAR
	if err := a.downloadServerJar(version, dir); err != nil {
		return fmt.Errorf("下载服务器文件失败: %v", err)
	}

	// 预创建 eula.txt
	if err := os.WriteFile(filepath.Join(dir, "eula.txt"), []byte("# By changing the setting below to TRUE you are indicating your agreement to our EULA (https://aka.ms/MinecraftEULA).\neula=true\n"), 0644); err != nil {
		return fmt.Errorf("创建 eula.txt 失败: %v", err)
	}

	// 预创建 server.properties
	properties := fmt.Sprintf("server-port=%d\nonline-mode=%v\nmotd=%s\n", port, onlineMode, name)
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(properties), 0644); err != nil {
		return fmt.Errorf("创建 server.properties 失败: %v", err)
	}

	return nil
}

// downloadServerJar 下载服务器 JAR 文件（参考 PCL 逻辑）
