package main

import (
	"fmt"
)

func formatMaxVer(maxMajor int) string {
	if maxMajor <= 0 {
		return "无上限"
	}
	return fmt.Sprintf("%d", maxMajor)
}

// GetJavaInfo 获取指定路径的 Java 信息（供前端调用）
