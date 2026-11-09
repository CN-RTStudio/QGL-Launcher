package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

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
