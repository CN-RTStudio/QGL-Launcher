package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

func (a *App) GetGuestPermissions() GuestPermissions {
	perms := DefaultGuestPermissions()
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return perms
	}
	guestPath := filepath.Join(a.userDirFor(currentUser.Dir), "guest.json")
	data, err := os.ReadFile(guestPath)
	if err != nil {
		return perms
	}
	var saved GuestPermissions
	if json.Unmarshal(data, &saved) == nil {
		return saved
	}
	return perms
}

// SetGuestPermissions 保存当前用户的访客权限到 guest.json
