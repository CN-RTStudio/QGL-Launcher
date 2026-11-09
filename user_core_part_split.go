package main

import (
	"fmt"
	"os"
)

func (a *App) GetUsers() ([]UserInfo, error) {
	usersDir := a.GetUsersDir()
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil, fmt.Errorf("读取用户目录失败: %w", err)
	}
	var users []UserInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		username := entry.Name()
		if err := validateUsername(username); err != nil {
			continue
		}
		hasPwd, err := a.UserHasPassword(username)
		if err != nil {
			hasPwd = false
		}
		userType := a.GetUserType(username)
		isLocked := false
		if userType == UserTypeGuest {
			isLocked = !a.guestUnlocked
		}
		serverName := ""
		if userType == UserTypeExternal {
			extData, extErr := a.GetExternalAuthData(username)
			if extErr == nil {
				serverName = extData.ServerName
			}
		}
		users = append(users, UserInfo{
			Username:    username,
			HasPassword: hasPwd,
			Type:        userType,
			IsLocked:    isLocked,
			ServerName:  serverName,
		})
	}
	return users, nil
}
