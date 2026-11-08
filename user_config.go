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

func (a *App) SaveUserConfig(username string, config *UserConfig) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化用户配置失败: %w", err)
	}
	configPath := filepath.Join(userDir, "config.json")
	// 安全加固: 用户配置原子写、0600、拒绝符号链接写穿
	if err := secureWritePrivateFile(configPath, data); err != nil {
		return fmt.Errorf("写入用户配置文件失败: %w", err)
	}
	// 版本选择属启动执行目标类字段，本进程可信写入后同步刷新防篡改基线。
	if g, err := a.GetGlobalConfig(); err == nil {
		a.UpdateConfigGuardBaseline(a.configSnapshotOf(g, config))
	}
	return nil
}

func (a *App) IsVersionIsolation() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	config, err := a.GetUserConfig(currentUser.Username)
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
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return fmt.Errorf("读取用户配置失败: %w", err)
	}
	config.VersionIsolation = enabled
	return a.SaveUserConfig(currentUser.Username, config)
}

func (a *App) GetSelectedVersion() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return ""
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return ""
	}
	return config.SelectedVersion
}

func (a *App) SetSelectedVersion(versionID string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	// versionID 随后会拼进 versions/<id> 路径，必须按单段安全路径名收口，
	// 拒绝 "../"、分隔符、保留设备名与控制字符，防止配置投毒演变成路径穿越。
	safeID, reason := SafeVersionID(versionID)
	if reason != configRejectNone {
		recordSecurityEvent(auditCategoryConfig, auditSeverityWarn, auditActionRejected,
			"SetSelectedVersion", "拒绝非法版本ID: "+reason)
		return fmt.Errorf("无效的版本标识: %s", reason)
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.SelectedVersion = safeID
	return a.SaveUserConfig(currentUser.Username, config)
}

// GetThemeColor 获取当前用户的主题色
func (a *App) GetThemeColor() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return "cyan"
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil || config.ThemeColor == "" {
		return "cyan"
	}
	return config.ThemeColor
}

// SetThemeColor 设置当前用户的主题色
