package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) getServerConfig(name string) (*ServerConfig, error) {
	serverDir := a.GetServerDir()
	configPath := filepath.Join(serverDir, name, "QGL", "config.json")

	// 也检查自定义目录
	data, err := os.ReadFile(configPath)
	if err != nil {
		// 尝试从服务器列表中查找
		list, listErr := a.GetServerList()
		if listErr != nil {
			return nil, fmt.Errorf("读取配置失败: %v", err)
		}
		for _, s := range list {
			if s.Name == name {
				return &s, nil
			}
		}
		return nil, fmt.Errorf("找不到服务器 %s", name)
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %v", err)
	}
	return &cfg, nil
}

// SetServerOnlineMode 设置服务器正版验证（需要重启）
