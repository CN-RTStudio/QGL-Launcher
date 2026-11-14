package main

import (

)

func (a *App) CreateOfflineUser(username string, password string) (string, error) {
	dir, err := a.CreateUser(username, password)
	if err != nil {
		return "", err
	}
	return dir, a.saveUserType(dir, UserTypeOffline)
}

// CreatePremiumUser 创建正版用户，返回用户标识 dir
func (a *App) CreatePremiumUser(username string, authData MSAuthData) (string, error) {
	// 用户已存在（令牌过期重新登录）：只更新 ms_auth.json，不重置用户配置
	// 按 显示用户名+类型 在注册表中查找，同名不同类型的用户互不影响
	if entry := a.findUserByNameAndType(username, UserTypePremium); entry != nil {
		if err := a.SaveMSAuthData(entry.Dir, &authData); err != nil {
			return "", err
		}
		return entry.Dir, a.saveUserType(entry.Dir, UserTypePremium)
	}
	// 创建用户目录和基础配置（不设置密码）
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	// 保存用户类型为正版
	if err := a.saveUserType(dir, UserTypePremium); err != nil {
		return "", err
	}
	// 保存微软认证数据
	return dir, a.SaveMSAuthData(dir, &authData)
}

// CreateExternalUser 创建外置用户，返回用户标识 dir
