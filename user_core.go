package main

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
