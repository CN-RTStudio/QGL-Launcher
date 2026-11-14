package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) DeleteCurrentUser(password string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	if err := validateUsername(currentUser.Username); err != nil {
		return err
	}
	if currentUser.Type == UserTypeGuest {
		return fmt.Errorf("访客用户不可删除")
	}

	usersDir := filepath.Clean(a.GetUsersDir())
	userDir := filepath.Join(usersDir, currentUser.Username)
	if !strings.HasPrefix(userDir, usersDir+string(os.PathSeparator)) {
		return fmt.Errorf("用户目录越界")
	}

	pwdPath := filepath.Join(userDir, "password.json")
	existing, err := readPasswordData(pwdPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("读取密码文件失败: %w", err)
	}
	if existing.PasswordHash != "" {
		if password == "" {
			return fmt.Errorf("该用户已设置密码，请输入密码")
		}
		if !verifyPassword(password, existing.PasswordHash) {
			return fmt.Errorf("密码错误")
		}
	}

	config, err := a.GetGlobalConfig()
	if err == nil && config.CurrentUser == currentUser.Username {
		config.CurrentUser = ""
		if err := a.SaveGlobalConfig(config); err != nil {
			return fmt.Errorf("清除当前用户失败: %w", err)
		}
	}

	if err := os.RemoveAll(userDir); err != nil {
		return fmt.Errorf("删除用户目录失败: %w", err)
	}
	return nil
}
