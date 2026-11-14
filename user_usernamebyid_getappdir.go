package main

import (
	"os"
	"path/filepath"

)

func (a *App) GetAppDir() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exePath)
}

func (a *App) GetQGLDir() string {
	return filepath.Join(a.GetAppDir(), "QGL")
}

func (a *App) GetUsersDir() string {
	return filepath.Join(a.GetQGLDir(), "Users")
}

// GetPortableJavaPath 获取便携版 Java 路径
