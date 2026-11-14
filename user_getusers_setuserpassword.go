package main

import (
	"crypto/md5"
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
