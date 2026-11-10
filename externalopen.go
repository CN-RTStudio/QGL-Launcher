package main

import (
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
)

const maxBrowserURLLen = 4096

type BrowserURLError struct {
	Code   string
	Detail string
}

func (e *BrowserURLError) Error() string {
	if e == nil {
		return ""
	}
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}
func browserURLError(code, detail string) *BrowserURLError {
	return &BrowserURLError{Code: code, Detail: detail}
}
func isPrivateOrLocalIP(ip net.IP) bool {
	return isNonPublicIP(ip)
}
func ipLiteralFromHost(host string) (net.IP, bool) {
	h := strings.TrimPrefix(host, "[")
	h = strings.TrimSuffix(h, "]")
	if h == "" {
		return nil, false
	}
	return parseDestIP(h)
}

func ValidateBrowserURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", browserURLError("browser-url-empty", "URL 为空")
	}
	if len(raw) > maxBrowserURLLen {
		return "", browserURLError("browser-url-long", "URL 过长")
	}
	// 任何 ASCII 控制字符（含 CR/LF/Tab/NUL）都拒绝：这类字符交给系统打开器可能触发
	// 参数 / 协议行截断，绝不能出现在将要被“当一条 URL 解释”的字符串里。
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "", browserURLError("browser-url-control", "URL 含控制字符")
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", browserURLError("browser-url-parse", err.Error())
	}
	if u.Scheme != "https" {
		return "", browserURLError("browser-url-scheme", "只允许 https:// 链接")
	}
	if u.User != nil {
		return "", browserURLError("browser-url-userinfo", "链接不允许携带用户名/密码(userinfo)")
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return "", browserURLError("browser-url-no-host", "链接缺少主机名")
	}
	// 不允许用反斜杠 / @ 等做视觉混淆（url.Parse 已处理 @，这里再堵路径里的反斜杠）。
	if strings.ContainsAny(host, `\/'"`) {
		return "", browserURLError("browser-url-bad-host", "主机名含非法字符")
	}
	if port := u.Port(); port != "" && port != "443" {
		return "", browserURLError("browser-url-port", "只允许默认 443 端口")
	}

	if ip, ok := ipLiteralFromHost(host); ok {
		if isPrivateOrLocalIP(ip) {
			return "", browserURLError("browser-url-internal-ip", "不允许打开指向本机/内网/链路本地的 IP 链接")
		}
		// 即使是公网 IP 字面量也拒绝：厂商下载页应以域名给出，直接打开 IP 常用于绕过
		// 域名认知做钓鱼，且不利于用户核对地址。
		return "", browserURLError("browser-url-ip-literal", "请使用域名链接而非裸 IP")
	}

	// 域名形态校验：必须含至少一个点、TLD 至少 2 个字母，标签合法。
	if !strings.Contains(host, ".") {
		return "", browserURLError("browser-url-single-label", "链接主机名缺少域名后缀")
	}
	labels := strings.Split(host, ".")
	for i, label := range labels {
		if label == "" {
			return "", browserURLError("browser-url-empty-label", "域名含空标签")
		}
		if i == len(labels)-1 {
			if len(label) < 2 {
				return "", browserURLError("browser-url-tld", "顶级域名长度异常")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z') {
					return "", browserURLError("browser-url-tld-alpha", "顶级域名必须为字母")
				}
			}
			continue
		}
		if !isDomainLabel(label) {
			return "", browserURLError("browser-url-bad-label", "域名标签含非法字符")
		}
	}
	return raw, nil
}

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
