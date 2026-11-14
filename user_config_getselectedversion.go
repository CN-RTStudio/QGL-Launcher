package main

import (
	"fmt"
)

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
