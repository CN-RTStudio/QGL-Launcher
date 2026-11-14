package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

func (a *App) GetServerList() ([]ServerConfig, error) {
	serverDir := a.GetServerDir()
	if _, err := os.Stat(serverDir); os.IsNotExist(err) {
		return []ServerConfig{}, nil
	}

	entries, err := os.ReadDir(serverDir)
	if err != nil {
		return nil, err
	}

	var list []ServerConfig
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		configPath := filepath.Join(serverDir, entry.Name(), "QGL", "config.json")
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		var cfg ServerConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}
		list = append(list, cfg)
	}
	return list, nil
}

// CreateServer 创建服务器
