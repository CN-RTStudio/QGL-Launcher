package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

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
