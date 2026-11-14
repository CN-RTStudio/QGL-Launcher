package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

func isDomainLabel(label string) bool {
	if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

func BrowserOpenCommand(raw string) (*exec.Cmd, error) {
	clean, err := ValidateBrowserURL(raw)
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", clean), nil
	case "darwin":
		return exec.Command("open", clean), nil
	default:
		return exec.Command("xdg-open", clean), nil
	}
}

// runValidatedBrowserURL 是给“校验失败即放弃”场景的便捷封装：命令已由
// BrowserOpenCommand 构造（不含 shell），这里负责启动；需要隐藏窗口的调用方可直接
// 使用 BrowserOpenCommand 拿到 *exec.Cmd 后自行设置 SysProcAttr 再 Start。
func runValidatedBrowserURL(raw string) error {
	cmd, err := BrowserOpenCommand(raw)
	if err != nil {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"externalopen", fmt.Sprintf("拦截不安全的浏览器打开请求: %v", err))
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("打开浏览器失败: %w", err)
	}
	return nil
}
