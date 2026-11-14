package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) UserHasPassword(id string) (bool, error) {
	pwdPath := filepath.Join(a.userDirFor(id), "password.json")
	info, err := os.Stat(pwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("检查密码文件失败: %w", err)
	}
	if info.Size() == 0 {
		return false, nil
	}
	pwdBytes, err := os.ReadFile(pwdPath)
	if err != nil {
		return false, fmt.Errorf("读取密码文件失败: %w", err)
	}
	var pwdData PasswordData
	if err := json.Unmarshal(pwdBytes, &pwdData); err != nil {
		return false, nil
	}
	return pwdData.PasswordMD5 != "", nil
}

