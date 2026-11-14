package main

import (
	"errors"
	"fmt"
	"os"
)

func fileSupportsADS(targetPath string) error {
	info, err := os.Lstat(targetPath)
	if err != nil {
		return fmt.Errorf("无法读取目标文件状态: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("拒绝给符号链接写入 MOTW")
	}
	if !info.Mode().IsRegular() {
		return errors.New("拒绝给非普通文件写入 MOTW")
	}
	return nil
}

// applyMarkOfTheWeb 在 targetPath 的 Zone.Identifier 数据流写入 Internet 区标记。
// 返回 applied=false 且 err==nil 表示当前平台不支持（非 Windows），调用方
// 应当作正常情况跳过；applied=true 表示标记已写入或覆盖。
func applyMarkOfTheWeb(targetPath, sourceURL string) (bool, error) {
	return applyMarkOfTheWebWithReferrer(targetPath, sourceURL, "")
}

// applyMarkOfTheWebWithReferrer 与 applyMarkOfTheWeb 相同，但允许附带发起页 URL。
