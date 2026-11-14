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
