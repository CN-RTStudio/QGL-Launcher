package main

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
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

// GlobalConfig 全局配置
type GlobalConfig struct {
	CurrentUser  string `json:"currentUser"`
	JavaPath     string `json:"javaPath"`
	MaxMemory    int    `json:"maxMemory"`
	MinMemory    int    `json:"minMemory"`
	MinecraftDir string `json:"minecraftDir"` // 自定义 .minecraft 目录，留空则使用默认路径
	PortableMode bool   `json:"portableMode"` // 便携版模式：优先使用 QGL\pe\java\bin\java.exe
}

// validateUsername 安全加固: 校验用户名，防止路径遍历
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("用户名不能为空")
	}
	if len(username) > 64 {
		return fmt.Errorf("用户名过长")
	}
	// 禁止路径遍历字符
	if strings.Contains(username, "..") || strings.Contains(username, "/") || strings.Contains(username, "\\") {
		return fmt.Errorf("用户名包含非法字符")
	}
	// 禁止控制字符
	for _, c := range username {
		if c < 32 || c == 127 {
			return fmt.Errorf("用户名包含控制字符")
		}
	}
	// 账户名最终会拼成 Users/<name>/ 目录段，再走一次统一的落盘名单段内核，
	// 补齐上面旧检查漏掉的 Windows 保留设备名、ADS 冒号与不可见 / 双向覆写 Unicode。
	if _, why := SafeAccountName(username); why != nameRejectNone {
		return fmt.Errorf("用户名未通过安全校验: %s", describeNameReject(why))
	}
	return nil
}

// hashPassword 安全加固: 使用 bcrypt 哈希密码
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// verifyPassword 安全加固: 使用 bcrypt 验证密码
