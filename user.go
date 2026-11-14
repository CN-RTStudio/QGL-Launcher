package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

// UserInfo 用户信息
type UserInfo struct {
	Username    string   `json:"username"`
	Dir         string   `json:"dir"`       // 用户文件夹名（随机字符串，作为用户唯一标识）
	HasPassword bool     `json:"hasPassword"`
	Type        UserType `json:"type"`
	IsLocked    bool     `json:"isLocked"`
	ServerName  string   `json:"serverName"` // 外置用户的服务器名称
	ServerURL   string   `json:"serverUrl"`  // 外置用户的验证服务器地址（令牌过期重新登录时预填）
}

// UserEntry 用户注册表条目（QGL/Users/user.json）
// name 为显示用户名（可重复），dir 为随机文件夹名（唯一标识），
// 这样不同模式的用户即使同名也不会互相覆盖
type UserEntry struct {
	Name string   `json:"name"` // 显示用户名
	Type UserType `json:"type"` // 用户类型
	Dir  string   `json:"dir"`  // 用户文件夹名（随机字符串）
}

// userRegistryPath 用户注册表路径
func (a *App) userRegistryPath() string {
	return filepath.Join(a.GetUsersDir(), "user.json")
}

// randomDirName 生成随机文件夹名（16 位十六进制）
func randomDirName() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// loadUserRegistry 读取用户注册表；若不存在 user.json 且有旧版用户文件夹则自动迁移转换
func (a *App) loadUserRegistry() []UserEntry {
	data, err := os.ReadFile(a.userRegistryPath())
	if err == nil {
		var entries []UserEntry
		if json.Unmarshal(data, &entries) == nil && entries != nil {
			return entries
		}
	}
	// 迁移：旧版以用户名作为文件夹名，转换为随机文件夹名
	return a.migrateUserRegistry()
}

// migrateUserRegistry 旧版用户目录迁移：文件夹名(用户名) -> 随机文件夹名 + user.json 注册表
func (a *App) migrateUserRegistry() []UserEntry {
	usersDir := a.GetUsersDir()
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return []UserEntry{}
	}

	var result []UserEntry
	migrated := false
	oldCurrent := ""
	if config, err := a.GetGlobalConfig(); err == nil {
		oldCurrent = config.CurrentUser
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		oldName := entry.Name()
		newDir := randomDirName()
		// 文件夹重命名失败（如被占用）则保留原名，同样注册进注册表，不影响使用
		if renameErr := os.Rename(filepath.Join(usersDir, oldName), filepath.Join(usersDir, newDir)); renameErr == nil {
			migrated = true
		} else {
			newDir = oldName
		}
		userType := a.readLegacyUserType(filepath.Join(usersDir, newDir))
		result = append(result, UserEntry{Name: oldName, Type: userType, Dir: newDir})
		// 同步修正全局配置中的当前用户
		if oldCurrent == oldName {
			if config, err := a.GetGlobalConfig(); err == nil {
				config.CurrentUser = newDir
				a.SaveGlobalConfig(config)
			}
		}
	}

	a.saveUserRegistry(result)
	if migrated && len(result) > 0 {
		a.writeLog("用户目录已迁移到随机文件夹名机制（共 %d 个用户）", len(result))
	}
	return result
}

// readLegacyUserType 从用户文件夹的 type.json 读取用户类型（迁移用）
func (a *App) readLegacyUserType(userDir string) UserType {
	data, err := os.ReadFile(filepath.Join(userDir, "type.json"))
	if err != nil {
		return UserTypeOffline
	}
	var typeData struct {
		Type UserType `json:"type"`
	}
	if json.Unmarshal(data, &typeData) != nil {
		return UserTypeOffline
	}
	return typeData.Type
}

// saveUserRegistry 保存用户注册表
func (a *App) saveUserRegistry(entries []UserEntry) error {
	os.MkdirAll(a.GetUsersDir(), 0755)
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.userRegistryPath(), data, 0644)
}

// findUserEntry 按标识（dir）查找注册表条目
func (a *App) findUserEntry(id string) *UserEntry {
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Dir == id {
			return &entries[i]
		}
	}
	return nil
}

// userNameByID 按标识（dir）查显示用户名（查不到返回原值，兼容迁移前调用）
func (a *App) userNameByID(id string) string {
	if entry := a.findUserEntry(id); entry != nil {
		return entry.Name
	}
	return id
}

// userDirFor 用户文件夹路径（标识 = 随机文件夹名）
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
func (a *App) GetOOBEDone() (bool, error) {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return false, err
	}
	return config.OOBE, nil
}

// SetOOBEDone 标记 OOBE 已完成
func (a *App) SetOOBEDone() error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}
	config.OOBE = true
	return a.SaveGlobalConfig(config)
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

// GetPortableJavaPath 获取便携版 Java 路径
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
