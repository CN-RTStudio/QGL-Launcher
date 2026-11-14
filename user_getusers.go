package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) GetUsers() ([]UserInfo, error) {
	entries := a.loadUserRegistry()

	var users []UserInfo
	for _, entry := range entries {
		hasPwd, err := a.UserHasPassword(entry.Dir)
		if err != nil {
			hasPwd = false
		}
		userType := entry.Type
		isLocked := false
		if userType == UserTypeGuest {
			isLocked = !a.guestUnlocked
		}
		serverName := ""
		serverURL := ""
		if userType == UserTypeExternal {
			extData, extErr := a.GetExternalAuthData(entry.Dir)
			if extErr == nil {
				serverName = extData.ServerName
				serverURL = extData.ServerURL
			}
		}
		users = append(users, UserInfo{
			Username:    entry.Name,
			Dir:         entry.Dir,
			HasPassword: hasPwd,
			Type:        userType,
			IsLocked:    isLocked,
			ServerName:  serverName,
			ServerURL:   serverURL,
		})
	}
	return users, nil
}

// CreateGuestUser 创建访客用户（需要安全密码），返回用户标识 dir
func (a *App) CreateGuestUser(username string, securityPassword string) (string, error) {
	if securityPassword == "" {
		return "", fmt.Errorf("访客用户必须设置安全密码")
	}
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	// 访客用户的密码文件存储安全密码
	userDir := a.userDirFor(dir)
	hash := md5.Sum([]byte(securityPassword))
	pwdData := PasswordData{
		PasswordMD5: fmt.Sprintf("%x", hash),
	}
	pwdBytes, err := json.MarshalIndent(pwdData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化密码数据失败: %w", err)
	}
	pwdPath := filepath.Join(userDir, "password.json")
	if err := os.WriteFile(pwdPath, pwdBytes, 0644); err != nil {
		return "", fmt.Errorf("写入密码文件失败: %w", err)
	}
	// 保存用户类型为访客
	return dir, a.saveUserType(dir, UserTypeGuest)
}

// CreateOfflineUser 创建离线用户（可选密码），返回用户标识 dir
func (a *App) CreateOfflineUser(username string, password string) (string, error) {
	dir, err := a.CreateUser(username, password)
	if err != nil {
		return "", err
	}
	return dir, a.saveUserType(dir, UserTypeOffline)
}

// CreatePremiumUser 创建正版用户，返回用户标识 dir
func (a *App) CreatePremiumUser(username string, authData MSAuthData) (string, error) {
	// 用户已存在（令牌过期重新登录）：只更新 ms_auth.json，不重置用户配置
	// 按 显示用户名+类型 在注册表中查找，同名不同类型的用户互不影响
	if entry := a.findUserByNameAndType(username, UserTypePremium); entry != nil {
		if err := a.SaveMSAuthData(entry.Dir, &authData); err != nil {
			return "", err
		}
		return entry.Dir, a.saveUserType(entry.Dir, UserTypePremium)
	}
	// 创建用户目录和基础配置（不设置密码）
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	// 保存用户类型为正版
	if err := a.saveUserType(dir, UserTypePremium); err != nil {
		return "", err
	}
	// 保存微软认证数据
	return dir, a.SaveMSAuthData(dir, &authData)
}

// CreateExternalUser 创建外置用户，返回用户标识 dir
func (a *App) CreateExternalUser(username string, authData ExternalAuthData) (string, error) {
	// 按 显示用户名+类型 在注册表中查找（外置登录令牌过期重加场景）
	if entry := a.findUserByNameAndType(username, UserTypeExternal); entry != nil {
		if err := a.SaveExternalAuthData(entry.Dir, &authData); err != nil {
			return "", err
		}
		return entry.Dir, nil
	}
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	if err := a.saveUserType(dir, UserTypeExternal); err != nil {
		return "", err
	}
	return dir, a.SaveExternalAuthData(dir, &authData)
}

// findUserByNameAndType 按显示用户名+类型查找注册表条目（同名不同类型不冲突）
func (a *App) findUserByNameAndType(name string, userType UserType) *UserEntry {
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Name == name && entries[i].Type == userType {
			return &entries[i]
		}
	}
	return nil
}

// SaveExternalAuthData 保存外置登录认证数据（加密存储，和正版账号一样；参数为用户标识 dir）
func (a *App) SaveExternalAuthData(id string, authData *ExternalAuthData) error {
	userDir := a.userDirFor(id)
	if err := os.MkdirAll(userDir, 0755); err != nil {
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

	// 加密（密钥基于显示用户名，迁移重命名文件夹后仍可解密）
	key := getEncryptionKey(a.userNameByID(id))
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
	return os.WriteFile(filepath.Join(userDir, "external_auth.json"), data, 0644)
}

// GetExternalAuthData 获取外置登录认证数据（解密读取；参数为用户标识 dir）
func (a *App) GetExternalAuthData(id string) (*ExternalAuthData, error) {
	userDir := a.userDirFor(id)
	data, err := os.ReadFile(filepath.Join(userDir, "external_auth.json"))
	if err != nil {
		return nil, fmt.Errorf("读取外置认证数据失败: %w", err)
	}

	// 先尝试按加密格式解析
	var encData ExternalAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		// 加密格式：解密 Data 字段（密钥基于显示用户名）
		key := getEncryptionKey(a.userNameByID(id))
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

// CreateUser 创建用户基础方法：文件夹名使用随机字符串，注册进 user.json，返回用户标识 dir
func (a *App) CreateUser(username string, password string) (string, error) {
	dir := randomDirName()
	userDir := a.userDirFor(dir)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return "", fmt.Errorf("创建用户目录失败: %w", err)
	}

	// 注册进用户注册表（显示名可重复，dir 唯一）
	entries := a.loadUserRegistry()
	entries = append(entries, UserEntry{Name: username, Type: UserTypeOffline, Dir: dir})
	if err := a.saveUserRegistry(entries); err != nil {
		return "", fmt.Errorf("写入用户注册表失败: %w", err)
	}

	if password != "" {
		hash := md5.Sum([]byte(password))
		pwdData := PasswordData{
			PasswordMD5: fmt.Sprintf("%x", hash),
		}
		pwdBytes, err := json.MarshalIndent(pwdData, "", "  ")
		if err != nil {
			return "", fmt.Errorf("序列化密码数据失败: %w", err)
		}
		pwdPath := filepath.Join(userDir, "password.json")
		if err := os.WriteFile(pwdPath, pwdBytes, 0644); err != nil {
			return "", fmt.Errorf("写入密码文件失败: %w", err)
		}
	}

	defaultConfig := UserConfig{
		VersionIsolation: false,
		SelectedVersion:  "",
	}
	configBytes, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化用户配置失败: %w", err)
	}
	configPath := filepath.Join(userDir, "config.json")
	if err := os.WriteFile(configPath, configBytes, 0644); err != nil {
		return "", fmt.Errorf("写入用户配置文件失败: %w", err)
	}

	return dir, nil
}

// LoginUser 登录用户（参数为用户标识 dir）
func (a *App) LoginUser(id string, password string) error {
	userType := a.GetUserType(id)

	if userType == UserTypeGuest {
		// 访客用户：不需要密码即可进入，但进入后处于锁定状态
		a.guestUnlocked = false
		return a.SetCurrentUser(id)
	}

	if userType == UserTypePremium {
		// 正版用户：刷新令牌，如果刷新失败则需要重新登录
		if err := a.RefreshMicrosoftToken(id); err != nil {
			return fmt.Errorf("正版令牌已过期，请重新登录: %v", err)
		}
		return a.SetCurrentUser(id)
	}

	if userType == UserTypeExternal {
		// 外置用户：刷新令牌
		if err := a.RefreshExternalToken(id); err != nil {
			return fmt.Errorf("外置登录令牌已过期，请重新登录: %v", err)
		}
		return a.SetCurrentUser(id)
	}

	// 离线用户：正常密码验证
	hasPwd, err := a.UserHasPassword(id)
	if err != nil {
		return fmt.Errorf("检查用户密码失败: %w", err)
	}

	if hasPwd {
		if password == "" {
			return fmt.Errorf("该用户已设置密码，请输入密码")
		}
		pwdPath := filepath.Join(a.userDirFor(id), "password.json")
		pwdBytes, err := os.ReadFile(pwdPath)
		if err != nil {
			return fmt.Errorf("读取密码文件失败: %w", err)
		}
		var pwdData PasswordData
		if err := json.Unmarshal(pwdBytes, &pwdData); err != nil {
			return fmt.Errorf("解析密码文件失败: %w", err)
		}
		hash := md5.Sum([]byte(password))
		inputMD5 := fmt.Sprintf("%x", hash)
		if inputMD5 != pwdData.PasswordMD5 {
			return fmt.Errorf("密码错误")
		}
	} else {
		if password != "" {
			return fmt.Errorf("该用户未设置密码，无需输入密码")
		}
	}

	return a.SetCurrentUser(id)
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

	userDir := a.userDirFor(currentUser.Dir)
	pwdPath := filepath.Join(userDir, "password.json")
	pwdBytes, err := os.ReadFile(pwdPath)
	if err != nil {
		return fmt.Errorf("读取安全密码文件失败: %w", err)
	}
	var pwdData PasswordData
	if err := json.Unmarshal(pwdBytes, &pwdData); err != nil {
		return fmt.Errorf("解析安全密码文件失败: %w", err)
	}
	hash := md5.Sum([]byte(securityPassword))
	inputMD5 := fmt.Sprintf("%x", hash)
	if inputMD5 != pwdData.PasswordMD5 {
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

// ===== 用户管理（管理当前用户）=====

// getUserPasswordMD5 读取用户密码 MD5（无密码返回 ""；参数为用户标识 dir）
func (a *App) getUserPasswordMD5(id string) string {
	pwdPath := filepath.Join(a.userDirFor(id), "password.json")
	pwdBytes, err := os.ReadFile(pwdPath)
	if err != nil {
		return ""
	}
	var pwdData PasswordData
	if json.Unmarshal(pwdBytes, &pwdData) != nil {
		return ""
	}
	return pwdData.PasswordMD5
}

// SetUserPassword 设置/修改当前用户的密码
// 有原密码时必须先验证原密码；newPassword 为空则清除密码
func (a *App) SetUserPassword(oldPassword string, newPassword string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	userDir := a.userDirFor(currentUser.Dir)
	pwdPath := filepath.Join(userDir, "password.json")

	existingMD5 := a.getUserPasswordMD5(currentUser.Dir)
	if existingMD5 != "" {
		// 有密码：必须验证原密码
		if oldPassword == "" {
			return fmt.Errorf("请输入原密码")
		}
		hash := md5.Sum([]byte(oldPassword))
		if fmt.Sprintf("%x", hash) != existingMD5 {
			return fmt.Errorf("原密码错误")
		}
	}

	if newPassword == "" {
		// 清除密码
		if err := os.Remove(pwdPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("清除密码失败: %w", err)
		}
		return nil
	}

	if err := os.MkdirAll(userDir, 0755); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	hash := md5.Sum([]byte(newPassword))
	pwdData := PasswordData{PasswordMD5: fmt.Sprintf("%x", hash)}
	pwdBytes, err := json.MarshalIndent(pwdData, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化密码数据失败: %w", err)
	}
	if err := os.WriteFile(pwdPath, pwdBytes, 0644); err != nil {
		return fmt.Errorf("写入密码文件失败: %w", err)
	}
	return nil
}

// DeleteCurrentUser 删除当前用户账户
// 有密码时必须先验证密码（前端的确认弹窗为二次确认）
func (a *App) DeleteCurrentUser(password string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}

	existingMD5 := a.getUserPasswordMD5(currentUser.Dir)
	if existingMD5 != "" {
		if password == "" {
			return fmt.Errorf("该用户已设置密码，请输入密码")
		}
		hash := md5.Sum([]byte(password))
		if fmt.Sprintf("%x", hash) != existingMD5 {
			return fmt.Errorf("密码错误")
		}
	}

	// 清除全局当前用户，避免残留指向已删除的用户
	config, err := a.GetGlobalConfig()
	if err == nil {
		config.CurrentUser = ""
		a.SaveGlobalConfig(config)
	}

	// 从注册表移除该用户
	entries := a.loadUserRegistry()
	filtered := entries[:0]
	for _, e := range entries {
		if e.Dir != currentUser.Dir {
			filtered = append(filtered, e)
		}
	}
	a.saveUserRegistry(filtered)

	userDir := a.userDirFor(currentUser.Dir)
	if err := os.RemoveAll(userDir); err != nil {
		return fmt.Errorf("删除用户目录失败: %w", err)
	}

	a.writeLog("用户 %s 已删除", currentUser.Username)
	return nil
}

// ===== 访客权限管理（保存到访客用户目录的 guest.json）=====

// GuestPermissions 访客权限：控制访客锁定时可以使用哪些功能
// 注意：解锁状态下所有功能均可用，权限仅影响锁定状态
type GuestPermissions struct {
	AllowDownload bool `json:"allowDownload"` // 下载游戏
	AllowMod      bool `json:"allowMod"`      // MOD 管理
	AllowEasyQGL  bool `json:"allowEasyQGL"`  // Easy QGL
	AllowSettings bool `json:"allowSettings"` // 设置
	AllowQGLPlus  bool `json:"allowQGLPlus"`  // QGL+（一键开服/联机）
	AllowHelper   bool `json:"allowHelper"`   // 辅助模式
}

// DefaultGuestPermissions 默认访客权限（全部允许）
func DefaultGuestPermissions() GuestPermissions {
	return GuestPermissions{
		AllowDownload: true,
		AllowMod:      true,
		AllowEasyQGL:  true,
		AllowSettings: true,
		AllowQGLPlus:  true,
		AllowHelper:   true,
	}
}

// GetGuestPermissions 读取当前用户的访客权限（guest.json，不存在则返回默认全允许）
func (a *App) GetGuestPermissions() GuestPermissions {
	perms := DefaultGuestPermissions()
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return perms
	}
	guestPath := filepath.Join(a.userDirFor(currentUser.Dir), "guest.json")
	data, err := os.ReadFile(guestPath)
	if err != nil {
		return perms
	}
	var saved GuestPermissions
	if json.Unmarshal(data, &saved) == nil {
		return saved
	}
	return perms
}

// SetGuestPermissions 保存当前用户的访客权限到 guest.json
func (a *App) SetGuestPermissions(perms GuestPermissions) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	userDir := a.userDirFor(currentUser.Dir)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	guestPath := filepath.Join(userDir, "guest.json")
	data, err := json.MarshalIndent(perms, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化权限数据失败: %w", err)
	}
	if err := os.WriteFile(guestPath, data, 0644); err != nil {
		return fmt.Errorf("写入权限文件失败: %w", err)
	}
	return nil
}


func (a *App) SetCurrentUser(id string) error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}
	// CurrentUser 存储用户标识（随机文件夹名）
	config.CurrentUser = id
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
	// CurrentUser 为用户标识（随机文件夹名），从注册表解析显示用户名
	entry := a.findUserEntry(config.CurrentUser)
	displayName := config.CurrentUser
	if entry != nil {
		displayName = entry.Name
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
		Username:    displayName,
		Dir:         config.CurrentUser,
		HasPassword: hasPwd,
		Type:        userType,
		IsLocked:    isLocked,
	}, nil
}

func (a *App) UserHasPassword(id string) (bool, error) {
	pwdPath := filepath.Join(a.userDirFor(id), "password.json")
	info, err := os.Stat(pwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("检查密码文件失败: %w", err)
	}
	if info.Size() == 0 {
		return false, nil
	}
	pwdBytes, err := os.ReadFile(pwdPath)
	if err != nil {
		return false, fmt.Errorf("读取密码文件失败: %w", err)
	}
	var pwdData PasswordData
	if err := json.Unmarshal(pwdBytes, &pwdData); err != nil {
		return false, nil
	}
	return pwdData.PasswordMD5 != "", nil
}

