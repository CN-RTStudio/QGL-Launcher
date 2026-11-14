package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) GetGlobalConfig() (*GlobalConfig, error) {
	configPath := filepath.Join(a.GetQGLDir(), "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &GlobalConfig{}, nil
		}
		return nil, fmt.Errorf("读取全局配置失败: %w", err)
	}
	var config GlobalConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析全局配置失败: %w", err)
	}
	return &config, nil
}

func (a *App) SaveGlobalConfig(config *GlobalConfig) error {
	qglDir := a.GetQGLDir()
	if err := os.MkdirAll(qglDir, 0755); err != nil {
		return fmt.Errorf("创建QGL目录失败: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化全局配置失败: %w", err)
	}
	configPath := filepath.Join(qglDir, "config.json")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("写入全局配置失败: %w", err)
	}
	return nil
}

func (a *App) GetUserConfig(id string) (*UserConfig, error) {
	configPath := filepath.Join(a.userDirFor(id), "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &UserConfig{}, nil
		}
		return nil, fmt.Errorf("读取用户配置失败: %w", err)
	}
	var config UserConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析用户配置失败: %w", err)
	}
	return &config, nil
}

func (a *App) SaveUserConfig(id string, config *UserConfig) error {
	userDir := a.userDirFor(id)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化用户配置失败: %w", err)
	}
	configPath := filepath.Join(userDir, "config.json")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("写入用户配置失败: %w", err)
	}
	return nil
}

func (a *App) IsVersionIsolation() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return false
	}
	return config.VersionIsolation
}

func (a *App) SetVersionIsolation(enabled bool) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return fmt.Errorf("读取用户配置失败: %w", err)
	}
	config.VersionIsolation = enabled
	return a.SaveUserConfig(currentUser.Dir, config)
}

func (a *App) GetSelectedVersion() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return ""
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return ""
	}
	return config.SelectedVersion
}
