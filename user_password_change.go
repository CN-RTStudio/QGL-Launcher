package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (a *App) SetUserPassword(oldPassword string, newPassword string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	if err := validateUsername(currentUser.Username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), currentUser.Username)
	pwdPath := filepath.Join(userDir, "password.json")

	existing, err := readPasswordData(pwdPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("读取密码文件失败: %w", err)
	}
	if existing.PasswordHash != "" {
		if oldPassword == "" {
			return fmt.Errorf("请输入原密码")
		}
		if !verifyPassword(oldPassword, existing.PasswordHash) {
			return fmt.Errorf("原密码错误")
		}
	}

	if newPassword == "" {
		if err := os.Remove(pwdPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("清除密码失败: %w", err)
		}
		return nil
	}

	hash, err := hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("密码哈希失败: %w", err)
	}
	pwdData := PasswordData{PasswordHash: hash}
	data, err := json.MarshalIndent(pwdData, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化密码数据失败: %w", err)
	}
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	if err := secureWritePrivateFile(pwdPath, data); err != nil {
		return fmt.Errorf("写入密码文件失败: %w", err)
	}
	return nil
}
