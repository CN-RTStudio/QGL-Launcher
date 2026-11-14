package main

import (
	"os"
	"path/filepath"

)

func (a *App) GetPortableJavaInfo() *JavaEntry {
	javaPath := a.GetPortableJavaPath()
	if _, err := os.Stat(javaPath); err != nil {
		return nil
	}
	return validateJava(javaPath)
}

func (a *App) GetMinecraftDir() string {
	// 辅助模式：使用用户指定的外部 .minecraft 目录（绕过 PCL/HMCL 直接安装）
	config, err := a.GetGlobalConfig()
	if err == nil && config.HelperMode && config.HelperModeDir != "" {
		return config.HelperModeDir
	}
	// 优先使用自定义路径
	if err == nil && config.MinecraftDir != "" {
		return config.MinecraftDir
	}
	return filepath.Join(a.GetQGLDir(), ".minecraft")
}

