package main

import (
	"os"
	"path/filepath"
)

// GetBackgroundImage 获取当前用户的背景图片路径
func (a *App) GetBackgroundImage() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return ""
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return ""
	}
	return config.BackgroundImage
}

// allowedBackgroundRoots 列出允许作为背景图来源的根目录。
func (a *App) allowedBackgroundRoots() []string {
	roots := []string{filepath.Join(a.GetQGLDir(), "cache")}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots,
			filepath.Join(home, "Pictures"),
			filepath.Join(home, "Videos"),
		)
	}
	return roots
}

// isSafeBackgroundPath 校验背景图片路径：
//  1. 文件必须存在且是普通文件；
//  2. 扩展名必须是图片类型（走 sanitize.go 的白名单）；
//  3. 路径不能是符号链接；
//  4. 路径必须落在 QGL/cache 或用户 Pictures/Videos 目录下。
func (a *App) isSafeBackgroundPath(p string) bool {
	if p == "" || IsSymlink(p) {
		return false
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() || info.Size() > maxBackgroundImageBytes {
		return false
	}
	if !IsSafeImageExt(p) {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	for _, root := range a.allowedBackgroundRoots() {
		if _, ok := PathWithin(root, abs); ok {
			return true
		}
	}
	return false
}
