package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

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
