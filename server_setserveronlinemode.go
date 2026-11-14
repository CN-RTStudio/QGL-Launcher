package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

)

func (a *App) SetServerOnlineMode(name string, onlineMode bool) error {
	cfg, err := a.getServerConfig(name)
	if err != nil {
		return err
	}

	// 修改 server.properties
	propPath := filepath.Join(cfg.ServerDir, "server.properties")
	content := ""
	if data, err := os.ReadFile(propPath); err == nil {
		content = string(data)
	}

	lines := strings.Split(content, "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, "online-mode=") {
			lines[i] = "online-mode=" + strconv.FormatBool(onlineMode)
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, "online-mode="+strconv.FormatBool(onlineMode))
	}

	if err := os.WriteFile(propPath, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return fmt.Errorf("修改 server.properties 失败: %v", err)
	}

	// 更新 QGL 配置
	cfg.OnlineMode = onlineMode
	qglDir := filepath.Join(cfg.ServerDir, "QGL")
	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(filepath.Join(qglDir, "config.json"), cfgData, 0644)

	return nil
}

// GenerateConnectionCode 生成连接码和直连地址
