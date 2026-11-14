package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

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
