package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

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
