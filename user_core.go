package main

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"os"
	"path/filepath"
)

// UserType 用户类型
type UserType string

const (
	UserTypeGuest    UserType = "guest"    // 访客用户
	UserTypeOffline  UserType = "offline"  // 离线用户
	UserTypePremium  UserType = "premium"  // 正版用户
	UserTypeExternal UserType = "external" // 外置用户（Yggdrasil）
)

// 安全加固: bcrypt 成本因子
const bcryptCost = 12

// maxBackgroundImageBytes 限制背景图片最大 10MB，防止恶意 CDN 塞个多 G 文件。
const maxBackgroundImageBytes = 10 << 20

// maxBackgroundDataURLBytes 是背景图转 base64 读入内存时的硬上限（50MiB）。
// 刻意取宽，只拦会把内存打爆的异常文件；超限绝不读入。
const maxBackgroundDataURLBytes int64 = 50 << 20

// UserInfo 用户信息
type UserInfo struct {
	Username    string   `json:"username"`
	HasPassword bool     `json:"hasPassword"`
	Type        UserType `json:"type"`
	IsLocked    bool     `json:"isLocked"`
	ServerName  string   `json:"serverName"` // 外置用户的服务器名称
}

// ExternalAuthData 外置登录认证数据
type ExternalAuthData struct {
	ServerURL   string `json:"serverUrl"`   // Yggdrasil API 服务器地址（如 https://littleskin.cn/api/yggdrasil）
	AccessToken string `json:"accessToken"` // 访问令牌
	ClientToken string `json:"clientToken"` // 客户端令牌
	UUID        string `json:"uuid"`        // 玩家 UUID
	Username    string `json:"username"`    // 游戏内用户名
	Password    string `json:"password"`    // 登录密码（加密存储，用于刷新令牌）
	ServerName  string `json:"serverName"`  // 服务器显示名称
}

// PasswordData 密码数据
type PasswordData struct {
	PasswordHash string `json:"passwordHash"`
}

// UserConfig 用户配置（每个用户独立）
type UserConfig struct {
	VersionIsolation        bool   `json:"versionIsolation"`
	SelectedVersion         string `json:"selectedVersion"`
	ThemeColor              string `json:"themeColor"`              // 主题色: blue, cyan, pink, purple, orange, yellow, green
	BackgroundImage         string `json:"backgroundImage"`         // 自定义背景图片路径，留空则使用默认
	ShowExportLaunchCommand bool   `json:"showExportLaunchCommand"` // 显示导出启动命令按钮
}

func verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
func (a *App) GetAppDir() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exePath)
}
func (a *App) GetQGLDir() string {
	return filepath.Join(a.GetAppDir(), "QGL")
}
func (a *App) GetUsersDir() string {
	return filepath.Join(a.GetQGLDir(), "Users")
}
func (a *App) GetPortableJavaPath() string {
	return filepath.Join(a.GetQGLDir(), "pe", "java", "bin", "java.exe")
}

func (a *App) IsPortableMode() bool {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return false
	}
	return config.PortableMode
}
func (a *App) SetPortableMode(enabled bool) error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return err
	}
	config.PortableMode = enabled
	return a.SaveGlobalConfig(config)
}
func (a *App) GetPortableJavaInfo() *JavaEntry {
	javaPath := a.GetPortableJavaPath()
	if _, err := os.Stat(javaPath); err != nil {
		return nil
	}
	return validateJava(javaPath)
}

func (a *App) GetMinecraftDir() string {
	// 优先使用自定义路径
	config, err := a.GetGlobalConfig()
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

func (a *App) GetUserType(username string) UserType {
	if err := validateUsername(username); err != nil {
		return UserTypeOffline
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	typePath := filepath.Join(userDir, "type.json")
	var typeData struct {
		Type UserType `json:"type"`
	}
	if err := readPrivateStoreJSON(typePath, &typeData, "用户类型文件"); err != nil {
		return UserTypeOffline
	}
	return typeData.Type
}

// saveUserType 保存用户类型
func (a *App) saveUserType(username string, userType UserType) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return err
	}
	typeData := struct {
		Type UserType `json:"type"`
	}{Type: userType}
	data, err := json.MarshalIndent(typeData, "", "  ")
	if err != nil {
		return err
	}
	// 敏感文件统一走原子私有写：防半截写、防符号链接写穿、强制 0600。
	return secureWritePrivateFile(filepath.Join(userDir, "type.json"), data)
}
