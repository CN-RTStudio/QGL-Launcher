package main

import (

)

func (a *App) CreateExternalUser(username string, authData ExternalAuthData) (string, error) {
	// 按 显示用户名+类型 在注册表中查找（外置登录令牌过期重加场景）
	if entry := a.findUserByNameAndType(username, UserTypeExternal); entry != nil {
		if err := a.SaveExternalAuthData(entry.Dir, &authData); err != nil {
			return "", err
		}
		return entry.Dir, nil
	}
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	if err := a.saveUserType(dir, UserTypeExternal); err != nil {
		return "", err
	}
	return dir, a.SaveExternalAuthData(dir, &authData)
}

// findUserByNameAndType 按显示用户名+类型查找注册表条目（同名不同类型不冲突）
