package main

import (
	"fmt"
	"os"
	"strings"

)

func (a *App) ToggleMod(modFilePath string, enable bool) error {
	if _, err := os.Stat(modFilePath); err != nil {
		return fmt.Errorf("文件不存在: %s", modFilePath)
	}

	var newPath string
	if enable {
		if strings.HasSuffix(strings.ToLower(modFilePath), ".jar.disabled") {
			newPath = modFilePath[:len(modFilePath)-len(".disabled")]
		} else {
			return nil
		}
	} else {
		if strings.HasSuffix(strings.ToLower(modFilePath), ".jar") {
			newPath = modFilePath + ".disabled"
		} else {
			return nil
		}
	}

	if err := os.Rename(modFilePath, newPath); err != nil {
		return fmt.Errorf("重命名失败: %v", err)
	}

	return nil
}

// ImportMod 导入 Mod 文件
