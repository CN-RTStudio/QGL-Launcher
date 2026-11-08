package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
