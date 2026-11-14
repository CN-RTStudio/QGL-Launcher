package main

import (
	"path/filepath"

)

func (a *App) userDirFor(id string) string {
	return filepath.Join(a.GetUsersDir(), id)
}

// ExternalAuthData 外置登录认证数据
type ExternalAuthData struct {
	ServerURL    string `json:"serverUrl"`    // Yggdrasil API 服务器地址（如 https://littleskin.cn/api/yggdrasil）
	AccessToken  string `json:"accessToken"`  // 访问令牌
	ClientToken  string `json:"clientToken"`  // 客户端令牌
	UUID         string `json:"uuid"`         // 玩家 UUID
	Username     string `json:"username"`     // 游戏内用户名
	Password     string `json:"password"`     // 登录密码（加密存储，用于刷新令牌）
	ServerName   string `json:"serverName"`   // 服务器显示名称
}

// PasswordData 密码数据
type PasswordData struct {
	PasswordMD5 string `json:"passwordMD5"`
}

// UserConfig 用户配置（每个用户独立）
type UserConfig struct {
	VersionIsolation         bool   `json:"versionIsolation"`
	SelectedVersion          string `json:"selectedVersion"`
	ThemeColor               string `json:"themeColor"`               // 主题色: blue, cyan, pink, purple, orange, yellow, green
	BackgroundImage          string `json:"backgroundImage"`           // 自定义背景图片路径，留空则使用默认
	ShowExportLaunchCommand  bool   `json:"showExportLaunchCommand"`   // 显示导出启动命令按钮
	OOBE                     bool   `json:"oobe"`                      // 用户向导是否已完成
}

// GlobalConfig 全局配置
type GlobalConfig struct {
	CurrentUser      string `json:"currentUser"`
	JavaPath         string `json:"javaPath"`
	MaxMemory        int    `json:"maxMemory"`
	MinMemory        int    `json:"minMemory"`
	MinecraftDir     string `json:"minecraftDir"`     // 自定义 .minecraft 目录，留空则使用默认路径
	PortableMode     bool   `json:"portableMode"`     // 便携版模式：优先使用 QGL\pe\java\bin\java.exe
	HelperMode       bool   `json:"helperMode"`       // 辅助模式：下载安装到外部 .minecraft（绕过 PCL/HMCL）
	HelperModeDir    string `json:"helperModeDir"`    // 辅助模式指定的 .minecraft 目录
	OOBE             bool   `json:"oobe"`             // OOBE 首次设置向导是否已完成
}

// GetOOBEDone 是否已完成 OOBE 首次设置向导
