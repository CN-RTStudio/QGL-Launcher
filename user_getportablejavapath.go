package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

func (a *App) GetPortableJavaPath() string {
	return filepath.Join(a.GetQGLDir(), "pe", "java", "bin", "java.exe")
}

// IsPortableMode 是否启用便携版模式
func (a *App) IsPortableMode() bool {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return false
	}
	return config.PortableMode
}

// SetPortableMode 设置便携版模式
func (a *App) SetPortableMode(enabled bool) error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return err
	}
	config.PortableMode = enabled
	return a.SaveGlobalConfig(config)
}

// GetPortableJavaInfo 获取便携版 Java 信息（如果存在）
func (a *App) GetPortableJavaInfo() *JavaEntry {
	javaPath := a.GetPortableJavaPath()
	if _, err := os.Stat(javaPath); err != nil {
		return nil
	}
	return validateJava(javaPath)
}

func (a *App) GetMinecraftDir() string {
	// 辅助模式：使用用户指定的外部 .minecraft 目录（绕过 PCL/HMCL 直接安装）
	config, err := a.GetGlobalConfig()
	if err == nil && config.HelperMode && config.HelperModeDir != "" {
		return config.HelperModeDir
	}
	// 优先使用自定义路径
	if err == nil && config.MinecraftDir != "" {
		return config.MinecraftDir
	}
	return filepath.Join(a.GetQGLDir(), ".minecraft")
}

func (a *App) CheckFirstRun() bool {
	usersDir := a.GetUsersDir()
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return true
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return false
		}
	}
	return true
}

// GetUserType 获取用户类型（参数为用户标识 dir）
func (a *App) GetUserType(id string) UserType {
	if entry := a.findUserEntry(id); entry != nil {
		return entry.Type
	}
	return a.readLegacyUserType(a.userDirFor(id))
}

// saveUserType 保存用户类型（参数为用户标识 dir，同步更新注册表）
func (a *App) saveUserType(id string, userType UserType) error {
	userDir := a.userDirFor(id)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return err
	}
	typeData := struct {
		Type UserType `json:"type"`
	}{Type: userType}
	data, err := json.MarshalIndent(typeData, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(userDir, "type.json"), data, 0644); err != nil {
		return err
	}
	// 同步注册表
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Dir == id {
			entries[i].Type = userType
			break
		}
	}
	return a.saveUserRegistry(entries)
}
