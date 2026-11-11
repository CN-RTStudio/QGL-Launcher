package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"os"
	"path/filepath"
	"strings"
)

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
