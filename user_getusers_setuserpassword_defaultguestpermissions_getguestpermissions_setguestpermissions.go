package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) SetGuestPermissions(perms GuestPermissions) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	userDir := a.userDirFor(currentUser.Dir)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	guestPath := filepath.Join(userDir, "guest.json")
	data, err := json.MarshalIndent(perms, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化权限数据失败: %w", err)
	}
	if err := os.WriteFile(guestPath, data, 0644); err != nil {
		return fmt.Errorf("写入权限文件失败: %w", err)
	}
	return nil
}


