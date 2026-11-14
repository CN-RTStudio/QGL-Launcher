package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (a *App) GetGlobalConfig() (*GlobalConfig, error) {
	configPath := filepath.Join(a.GetQGLDir(), "config.json")
	var config GlobalConfig
	if err := readPrivateStoreJSON(configPath, &config, "全局配置"); err != nil {
		if os.IsNotExist(err) {
			return &GlobalConfig{}, nil
		}
		return nil, fmt.Errorf("读取全局配置失败: %w", err)
	}
	if err := validateLoadedGlobalConfig(&config); err != nil {
		return nil, fmt.Errorf("全局配置不安全: %w", err)
	}
	return &config, nil
}
func (a *App) SaveGlobalConfig(config *GlobalConfig) error {
	qglDir := a.GetQGLDir()
	if err := os.MkdirAll(qglDir, 0700); err != nil {
		return fmt.Errorf("创建QGL目录失败: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化全局配置失败: %w", err)
	}
	configPath := filepath.Join(qglDir, "config.json")
	// 安全加固: 全局配置原子写、0600、拒绝符号链接写穿
	if err := secureWritePrivateFile(configPath, data); err != nil {
		return fmt.Errorf("写入全局配置失败: %w", err)
	}
	// 本进程可信写入后刷新防篡改基线（用户 UI 主动改配置不应被误判为外部篡改）。
	a.UpdateConfigGuardBaseline(a.configSnapshotOf(config, nil))
	return nil
}

func (a *App) GetUserConfig(username string) (*UserConfig, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	configPath := filepath.Join(a.GetUsersDir(), username, "config.json")
	var config UserConfig
	if err := readPrivateStoreJSON(configPath, &config, "用户配置"); err != nil {
		if os.IsNotExist(err) {
			return &UserConfig{}, nil
		}
		return nil, fmt.Errorf("读取用户配置失败: %w", err)
	}
	if err := validateLoadedUserConfig(&config); err != nil {
		return nil, fmt.Errorf("用户配置不安全: %w", err)
	}
	return &config, nil
}
