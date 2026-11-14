package main

import (

)

func (a *App) GetUsers() ([]UserInfo, error) {
	entries := a.loadUserRegistry()

	var users []UserInfo
	for _, entry := range entries {
		hasPwd, err := a.UserHasPassword(entry.Dir)
		if err != nil {
			hasPwd = false
		}
		userType := entry.Type
		isLocked := false
		if userType == UserTypeGuest {
			isLocked = !a.guestUnlocked
		}
		serverName := ""
		serverURL := ""
		if userType == UserTypeExternal {
			extData, extErr := a.GetExternalAuthData(entry.Dir)
			if extErr == nil {
				serverName = extData.ServerName
				serverURL = extData.ServerURL
			}
		}
		users = append(users, UserInfo{
			Username:    entry.Name,
			Dir:         entry.Dir,
			HasPassword: hasPwd,
			Type:        userType,
			IsLocked:    isLocked,
			ServerName:  serverName,
			ServerURL:   serverURL,
		})
	}
	return users, nil
}

// CreateGuestUser 创建访客用户（需要安全密码），返回用户标识 dir
