package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

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
