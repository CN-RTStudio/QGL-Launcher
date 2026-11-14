package main

import (
	"fmt"
	"os"

)

func (a *App) DeleteMod(modFilePath string) error {
	if _, err := os.Stat(modFilePath); err != nil {
		return fmt.Errorf("文件不存在: %s", modFilePath)
	}
	return os.Remove(modFilePath)
}

// downloadModItem 下载 Mod 文件
