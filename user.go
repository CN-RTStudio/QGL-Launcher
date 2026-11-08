package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
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

// GetUserType 获取用户类型
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

func (a *App) GetUsers() ([]UserInfo, error) {
	usersDir := a.GetUsersDir()
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil, fmt.Errorf("读取用户目录失败: %w", err)
	}
	var users []UserInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		username := entry.Name()
		if err := validateUsername(username); err != nil {
			continue
		}
		hasPwd, err := a.UserHasPassword(username)
		if err != nil {
			hasPwd = false
		}
		userType := a.GetUserType(username)
		isLocked := false
		if userType == UserTypeGuest {
			isLocked = !a.guestUnlocked
		}
		serverName := ""
		if userType == UserTypeExternal {
			extData, extErr := a.GetExternalAuthData(username)
			if extErr == nil {
				serverName = extData.ServerName
			}
		}
		users = append(users, UserInfo{
			Username:    username,
			HasPassword: hasPwd,
			Type:        userType,
			IsLocked:    isLocked,
			ServerName:  serverName,
		})
	}
	return users, nil
}

// CreateGuestUser 创建访客用户（需要安全密码）
func (a *App) CreateGuestUser(username string, securityPassword string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if securityPassword == "" {
		return fmt.Errorf("访客用户必须设置安全密码")
	}
	if err := a.CreateUser(username, ""); err != nil {
		return err
	}
	// 访客用户的密码文件存储安全密码
	userDir := filepath.Join(a.GetUsersDir(), username)
	// 安全加固: 使用 bcrypt 哈希密码
	hash, err := hashPassword(securityPassword)
	if err != nil {
		return fmt.Errorf("密码哈希失败: %w", err)
	}
	pwdData := PasswordData{
		PasswordHash: hash,
	}
	pwdBytes, err := json.MarshalIndent(pwdData, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化密码数据失败: %w", err)
	}
	pwdPath := filepath.Join(userDir, "password.json")
	// 安全加固: 密码文件权限 0600，且原子写 / 拒绝符号链接写穿
	if err := secureWritePrivateFile(pwdPath, pwdBytes); err != nil {
		return fmt.Errorf("写入密码文件失败: %w", err)
	}
	// 保存用户类型为访客
	return a.saveUserType(username, UserTypeGuest)
}

// CreateOfflineUser 创建离线用户（可选密码）
func (a *App) CreateOfflineUser(username string, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := a.CreateUser(username, password); err != nil {
		return err
	}
	return a.saveUserType(username, UserTypeOffline)
}

// CreatePremiumUser 创建正版用户
func (a *App) CreatePremiumUser(username string, authData MSAuthData) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	// 创建用户目录和基础配置（不设置密码）
	if err := a.CreateUser(username, ""); err != nil {
		return err
	}
	// 保存用户类型为正版
	if err := a.saveUserType(username, UserTypePremium); err != nil {
		return err
	}
	// 保存微软认证数据
	return a.SaveMSAuthData(username, &authData)
}

// CreateExternalUser 创建外置用户
func (a *App) CreateExternalUser(username string, authData ExternalAuthData) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := a.CreateUser(username, ""); err != nil {
		return err
	}
	if err := a.saveUserType(username, UserTypeExternal); err != nil {
		return err
	}
	return a.SaveExternalAuthData(username, &authData)
}

// SaveExternalAuthData 保存外置登录认证数据（加密存储，和正版账号一样）
func (a *App) SaveExternalAuthData(username string, authData *ExternalAuthData) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	// 构建需要加密的数据（除 serverName 以外的敏感字段）
	encryptPayload := map[string]interface{}{
		"serverUrl":   authData.ServerURL,
		"accessToken": authData.AccessToken,
		"clientToken": authData.ClientToken,
		"uuid":        authData.UUID,
		"username":    authData.Username,
		"password":    authData.Password,
	}
	payloadBytes, err := json.Marshal(encryptPayload)
	if err != nil {
		return fmt.Errorf("序列化外置认证数据失败: %w", err)
	}
	// 加密：外置认证数据与正版账号共用同一用户目录下的每用户随机盐 ms_auth.salt，
	// 保证同一用户不同凭据文件的密钥派生口径一致；盐缺失时生成，读不到则中止写入。
	saltPath := filepath.Join(userDir, "ms_auth.salt")
	salt, _, err := loadOrCreateAuthSalt(saltPath, true)
	if err != nil {
		return fmt.Errorf("准备认证盐失败: %w", err)
	}
	key := getEncryptionKey(username, salt)
	encrypted, err := aesGCMEncrypt(payloadBytes, key)
	if err != nil {
		return fmt.Errorf("加密外置认证数据失败: %w", err)
	}
	// 构建加密后的存储格式
	encData := ExternalAuthDataEncrypted{
		ServerName: authData.ServerName,
		Data:       encrypted,
	}
	data, err := json.MarshalIndent(encData, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化加密数据失败: %w", err)
	}
	// 安全加固: 认证数据文件权限 0600，原子写并拒绝符号链接写穿
	return secureWritePrivateFile(filepath.Join(userDir, "external_auth.json"), data)
}

// GetExternalAuthData 获取外置登录认证数据（解密读取）
func (a *App) GetExternalAuthData(username string) (*ExternalAuthData, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	data, err := readPrivateStoreBytes(filepath.Join(userDir, "external_auth.json"), "外置认证数据")
	if err != nil {
		return nil, fmt.Errorf("读取外置认证数据失败: %w", err)
	}
	// 先尝试按加密格式解析
	var encData ExternalAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		// 加密格式：解密 Data 字段。盐与写入侧一致；老数据没有盐文件时
		// loadOrCreateAuthSalt(create=false) 返回 nil，getEncryptionKey 回退旧硬编码盐。
		saltPath := filepath.Join(userDir, "ms_auth.salt")
		salt, _, _ := loadOrCreateAuthSalt(saltPath, false)
		key := getEncryptionKey(username, salt)
		decrypted, err := aesGCMDecrypt(encData.Data, key)
		if err != nil {
			return nil, fmt.Errorf("解密外置认证数据失败: %w", err)
		}
		var authData ExternalAuthData
		if err := json.Unmarshal(decrypted, &authData); err != nil {
			return nil, fmt.Errorf("解析解密后的外置认证数据失败: %w", err)
		}
		authData.ServerName = encData.ServerName // 服务器名称不加密
		return &authData, nil
	}
	// 兼容旧版明文格式
	var authData ExternalAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, fmt.Errorf("解析外置认证数据失败: %w", err)
	}
	return &authData, nil
}

// CreateUser 创建用户基础方法
func (a *App) CreateUser(username string, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	if password != "" {
		// 安全加固: 使用 bcrypt 哈希密码
		hash, err := hashPassword(password)
		if err != nil {
			return fmt.Errorf("密码哈希失败: %w", err)
		}
		pwdData := PasswordData{
			PasswordHash: hash,
		}
		pwdBytes, err := json.MarshalIndent(pwdData, "", "  ")
		if err != nil {
			return fmt.Errorf("序列化密码数据失败: %w", err)
		}
		pwdPath := filepath.Join(userDir, "password.json")
		// 安全加固: 密码文件原子写、0600、拒绝符号链接写穿
		if err := secureWritePrivateFile(pwdPath, pwdBytes); err != nil {
			return fmt.Errorf("写入密码文件失败: %w", err)
		}
	}
	defaultConfig := UserConfig{
		VersionIsolation: false,
		SelectedVersion:  "",
	}
	configBytes, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化用户配置失败: %w", err)
	}
	configPath := filepath.Join(userDir, "config.json")
	if err := secureWritePrivateFile(configPath, configBytes); err != nil {
		return fmt.Errorf("写入用户配置文件失败: %w", err)
	}
	return nil
}

func (a *App) LoginUser(username string, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userType := a.GetUserType(username)
	if userType == UserTypeGuest {
		// 访客用户：不需要密码即可进入，但进入后处于锁定状态
		a.guestUnlocked = false
		return a.SetCurrentUser(username)
	}
	if userType == UserTypePremium {
		// 正版用户：刷新令牌，如果刷新失败则需要重新登录
		if err := a.RefreshMicrosoftToken(username); err != nil {
			return fmt.Errorf("正版令牌已过期，请重新登录: %v", err)
		}
		return a.SetCurrentUser(username)
	}
	if userType == UserTypeExternal {
		// 外置用户：刷新令牌
		if err := a.RefreshExternalToken(username); err != nil {
			return fmt.Errorf("外置登录令牌已过期，请重新登录: %v", err)
		}
		return a.SetCurrentUser(username)
	}
	// 离线用户：正常密码验证
	hasPwd, err := a.UserHasPassword(username)
	if err != nil {
		return fmt.Errorf("检查用户密码失败: %w", err)
	}
	if hasPwd {
		if password == "" {
			return fmt.Errorf("该用户已设置密码，请输入密码")
		}
		userDir := filepath.Join(a.GetUsersDir(), username)
		pwdPath := filepath.Join(userDir, "password.json")
		pwdData, err := readPasswordData(pwdPath)
		if err != nil {
			return fmt.Errorf("读取密码文件失败: %w", err)
		}
		// 安全加固: 使用 bcrypt 验证密码
		if !verifyPassword(password, pwdData.PasswordHash) {
			return fmt.Errorf("密码错误")
		}
	} else {
		if password != "" {
			return fmt.Errorf("该用户未设置密码，无需输入密码")
		}
	}
	return a.SetCurrentUser(username)
}

// UnlockGuest 解锁访客用户（输入安全密码）
func (a *App) UnlockGuest(securityPassword string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	if currentUser.Type != UserTypeGuest {
		return fmt.Errorf("当前用户不是访客用户")
	}
	if securityPassword == "" {
		return fmt.Errorf("请输入安全密码")
	}
	userDir := filepath.Join(a.GetUsersDir(), currentUser.Username)
	pwdPath := filepath.Join(userDir, "password.json")
	pwdData, err := readPasswordData(pwdPath)
	if err != nil {
		return fmt.Errorf("读取安全密码文件失败: %w", err)
	}
	// 安全加固: 使用 bcrypt 验证密码
	if !verifyPassword(securityPassword, pwdData.PasswordHash) {
		return fmt.Errorf("安全密码错误")
	}
	a.guestUnlocked = true
	return nil
}

// IsGuestLocked 检查当前访客用户是否锁定
func (a *App) IsGuestLocked() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	if currentUser.Type != UserTypeGuest {
		return false
	}
	return !a.guestUnlocked
}

// LockGuest 重新锁定访客用户
func (a *App) LockGuest() {
	a.guestUnlocked = false
}

func (a *App) SetCurrentUser(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}
	config.CurrentUser = username
	return a.SaveGlobalConfig(config)
}

func (a *App) GetCurrentUser() (UserInfo, error) {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return UserInfo{}, fmt.Errorf("读取全局配置失败: %w", err)
	}
	if config.CurrentUser == "" {
		return UserInfo{}, fmt.Errorf("未设置当前用户")
	}
	if err := validateUsername(config.CurrentUser); err != nil {
		return UserInfo{}, fmt.Errorf("无效的用户名")
	}
	hasPwd, err := a.UserHasPassword(config.CurrentUser)
	if err != nil {
		hasPwd = false
	}
	userType := a.GetUserType(config.CurrentUser)
	isLocked := false
	if userType == UserTypeGuest {
		isLocked = !a.guestUnlocked
	}
	return UserInfo{
		Username:    config.CurrentUser,
		HasPassword: hasPwd,
		Type:        userType,
		IsLocked:    isLocked,
	}, nil
}

func (a *App) UserHasPassword(username string) (bool, error) {
	if err := validateUsername(username); err != nil {
		return false, err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	pwdPath := filepath.Join(userDir, "password.json")
	pwdData, err := readPasswordData(pwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		// 体积超限 / 符号链接 / 解析损坏一律 fail-closed 阻断登录，绝不能把一个
		// 被异常改写的密码文件当成“未设密码”，否则本地预置畸形文件即可绕过口令。
		return false, fmt.Errorf("读取密码文件失败: %w", err)
	}
	return pwdData.PasswordHash != "", nil
}

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
func (a *App) SetThemeColor(color string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	// 主题色会被前端读回用于 data-theme / 样式键，落盘前强制白名单，
	// 拒绝未知值与夹带控制字符 / 标记的配置投毒。
	safeColor, reason := SafeThemeColor(color)
	if reason != configRejectNone {
		recordSecurityEvent(auditCategoryConfig, auditSeverityWarn, auditActionRejected,
			"SetThemeColor", "拒绝非法主题色: "+reason)
		return fmt.Errorf("无效的主题色: %s", reason)
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.ThemeColor = safeColor
	err = a.SaveUserConfig(currentUser.Username, config)
	if err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "themeChanged", safeColor)
	return nil
}

// GetShowExportLaunchCommand 获取是否显示导出启动命令按钮
func (a *App) GetShowExportLaunchCommand() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return false
	}
	return config.ShowExportLaunchCommand
}

// SetShowExportLaunchCommand 设置是否显示导出启动命令按钮
func (a *App) SetShowExportLaunchCommand(show bool) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.ShowExportLaunchCommand = show
	return a.SaveUserConfig(currentUser.Username, config)
}

// GetBackgroundImage 获取当前用户的背景图片路径
func (a *App) GetBackgroundImage() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return ""
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return ""
	}
	return config.BackgroundImage
}

// allowedBackgroundRoots 列出允许作为背景图来源的根目录。
func (a *App) allowedBackgroundRoots() []string {
	roots := []string{filepath.Join(a.GetQGLDir(), "cache")}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots,
			filepath.Join(home, "Pictures"),
			filepath.Join(home, "Videos"),
		)
	}
	return roots
}

// isSafeBackgroundPath 校验背景图片路径：
//  1. 文件必须存在且是普通文件；
//  2. 扩展名必须是图片类型（走 sanitize.go 的白名单）；
//  3. 路径不能是符号链接；
//  4. 路径必须落在 QGL/cache 或用户 Pictures/Videos 目录下。
func (a *App) isSafeBackgroundPath(p string) bool {
	if p == "" || IsSymlink(p) {
		return false
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() || info.Size() > maxBackgroundImageBytes {
		return false
	}
	if !IsSafeImageExt(p) {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	for _, root := range a.allowedBackgroundRoots() {
		if _, ok := PathWithin(root, abs); ok {
			return true
		}
	}
	return false
}

// SetBackgroundImage 设置当前用户的背景图片路径
func (a *App) SetBackgroundImage(path string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	// 安全加固：不接受任意路径，只能是 Pictures/Videos 或 QGL/cache 下的图片
	if !a.isSafeBackgroundPath(path) {
		return fmt.Errorf("背景图片路径不安全或不在允许目录内")
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.BackgroundImage = path
	err = a.SaveUserConfig(currentUser.Username, config)
	if err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "backgroundChanged", path)
	return nil
}

// SelectBackgroundImage 打开文件选择对话框选择背景图片
func (a *App) SelectBackgroundImage() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择背景图片",
		Filters: []runtime.FileFilter{
			{DisplayName: "图片文件", Pattern: "*.jpg;*.jpeg;*.png;*.bmp;*.webp"},
		},
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// GetBackgroundImageDataURL 获取背景图片的 base64 Data URL（用于 CSS background-image）
func (a *App) GetBackgroundImageDataURL() string {
	path := a.GetBackgroundImage()
	if path == "" || !fileExists(path) {
		return ""
	}
	// 安全加固：即使 config 里残留了老路径，读之前再校一遍
	if !a.isSafeBackgroundPath(path) {
		return ""
	}
	url, err := a.fileToDataURL(path)
	if err != nil {
		return ""
	}
	return url
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetBingDailyImage 获取 Bing 每日壁纸图片
// 1. 请求 Bing API 获取重定向 URL
// 2. 跟随重定向获取实际图片
// 3. 缓存到本地并返回 data URL
func (a *App) GetBingDailyImage() (string, error) {
	cacheDir := filepath.Join(a.GetQGLDir(), "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", fmt.Errorf("创建缓存目录失败: %w", err)
	}
	cachePath := filepath.Join(cacheDir, "bing_daily.jpg")
	// 请求 Bing API（会重定向到图片 URL）
	client := safeHTTPClient()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// 不自动跟随重定向，我们需要获取最终的图片 URL
		return http.ErrUseLastResponse
	}
	resp, err := client.Get("https://bing.biturl.top/?resolution=1920&format=image&index=0&mkt=zh-CN")
	if err != nil {
		return "", fmt.Errorf("请求 Bing API 失败: %w", err)
	}
	defer resp.Body.Close()
	// 获取最终图片 URL（从 Location 头或响应体中）
	imageURL := ""
	if resp.StatusCode == 302 || resp.StatusCode == 301 || resp.StatusCode == 307 || resp.StatusCode == 308 {
		imageURL = resp.Header.Get("Location")
	} else if resp.StatusCode == 200 {
		// 有些 API 直接返回图片，限 10MB 防超大 body
		limited := io.LimitReader(resp.Body, maxBackgroundImageBytes)
		data, err := io.ReadAll(limited)
		if err != nil {
			return "", fmt.Errorf("读取响应失败: %w", err)
		}
		if len(data) >= maxBackgroundImageBytes {
			return "", fmt.Errorf("Bing 图片过大，已拒绝")
		}
		if err := secureWritePrivateFile(cachePath, data); err != nil {
			return "", fmt.Errorf("缓存图片失败: %w", err)
		}
		return a.fileToDataURL(cachePath)
	}
	if imageURL == "" {
		return "", fmt.Errorf("未获取到图片地址，状态码: %d", resp.StatusCode)
	}
	// 安全加固: 用 ValidateURL 统一校验
	if !ValidateURL(imageURL) {
		return "", fmt.Errorf("无效的图片 URL 协议")
	}
	// 下载实际图片
	imgResp, err := safeHTTPClient().Get(imageURL)
	if err != nil {
		return "", fmt.Errorf("下载图片失败: %w", err)
	}
	defer imgResp.Body.Close()
	if imgResp.StatusCode != 200 {
		return "", fmt.Errorf("下载失败，状态码: %d", imgResp.StatusCode)
	}
	// 限 10MB，防止恶意 CDN 塞个多 G 文件
	limited := io.LimitReader(imgResp.Body, maxBackgroundImageBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("读取图片数据失败: %w", err)
	}
	if len(data) >= maxBackgroundImageBytes {
		return "", fmt.Errorf("图片过大，已拒绝")
	}
	// 缓存到本地（原子写，防止预置符号链接把图片数据写穿到其它文件）
	if err := secureWritePrivateFile(cachePath, data); err != nil {
		return "", fmt.Errorf("缓存图片失败: %w", err)
	}
	// 设置为当前背景
	a.SetBackgroundImage(cachePath)
	return a.fileToDataURL(cachePath)
}

// GetCachedBingImage 获取缓存的 Bing 图片（如果存在）
func (a *App) GetCachedBingImage() string {
	cachePath := filepath.Join(a.GetQGLDir(), "cache", "bing_daily.jpg")
	if !fileExists(cachePath) {
		return ""
	}
	url, _ := a.fileToDataURL(cachePath)
	return url
}

func (a *App) fileToDataURL(path string) (string, error) {
	// 走统一的有界读取原语：stat 声明拦截 + LimitReader+1 兜底 + 拒绝符号链接/特殊文件，
	// 防止背景图被换成设备/管道或塞成超大文件把进程内存打爆。
	data, err := readBoundedFile(path, maxBackgroundDataURLBytes)
	if err != nil {
		return "", err
	}
	ext := strings.ToLower(filepath.Ext(path))
	mimeMap := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".bmp":  "image/bmp",
		".webp": "image/webp",
	}
	mimeType := mimeMap[ext]
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, b64), nil
}
