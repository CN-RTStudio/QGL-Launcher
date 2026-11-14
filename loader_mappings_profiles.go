package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func (a *App) ensureLauncherProfiles(mcDir string) {
	profilesPath := filepath.Join(mcDir, "launcher_profiles.json")
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		profiles := map[string]interface{}{
			"profiles": map[string]interface{}{},
		}
		// launcher_profiles.json 是启动器状态文件，有界原子私有写防半截写与符号链接写穿；
		// 序列化错误也不再被丢弃。
		if err := writePrivateJSON(profilesPath, profiles); err != nil {
			fmt.Printf("创建 launcher_profiles.json 失败: %v\n", err)
		}
	}
}
