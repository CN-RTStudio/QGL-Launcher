package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type GuestPermissions struct {
	AllowDownload bool `json:"allowDownload"`
	AllowMod      bool `json:"allowMod"`
	AllowEasyQGL  bool `json:"allowEasyQGL"`
	AllowSettings bool `json:"allowSettings"`
	AllowQGLPlus  bool `json:"allowQGLPlus"`
	AllowHelper   bool `json:"allowHelper"`
}

func DefaultGuestPermissions() GuestPermissions {
	return GuestPermissions{
		AllowDownload: true,
		AllowMod:      true,
		AllowEasyQGL:  true,
		AllowSettings: true,
		AllowQGLPlus:  true,
		AllowHelper:   true,
	}
}

func (a *App) guestPermissionsPath(username string) (string, error) {
	if err := validateUsername(username); err != nil {
		return "", err
	}
	return filepath.Join(a.GetUsersDir(), username, "guest.json"), nil
}

func (a *App) GetGuestPermissions() GuestPermissions {
	perms := DefaultGuestPermissions()
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return perms
	}
	path, err := a.guestPermissionsPath(currentUser.Username)
	if err != nil {
		return perms
	}
	var saved GuestPermissions
	if err := readPrivateStoreJSON(path, &saved, "访客权限"); err != nil {
		return perms
	}
	return saved
}

func (a *App) SetGuestPermissions(perms GuestPermissions) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	path, err := a.guestPermissionsPath(currentUser.Username)
	if err != nil {
		return fmt.Errorf("用户名校验失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	data, err := json.MarshalIndent(perms, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化权限数据失败: %w", err)
	}
	if err := secureWritePrivateFile(path, data); err != nil {
		return fmt.Errorf("写入权限文件失败: %w", err)
	}
	return nil
}
