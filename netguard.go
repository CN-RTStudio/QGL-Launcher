package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const maxDownloadURLLen = 2048

func blockedDownloadHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			return true
		}
		return false
	}
	return false
}

func validateDownloadURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("下载地址为空")
	}
	if len(raw) > maxDownloadURLLen {
		return fmt.Errorf("下载地址过长: %d", len(raw))
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == 0 || c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			return fmt.Errorf("下载地址包含非法字符")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("下载地址无法解析: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("下载地址协议不被允许: %q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("下载地址不允许携带用户信息")
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("下载地址缺少主机名")
	}
	if blockedDownloadHost(u.Hostname()) {
		return fmt.Errorf("下载地址指向本机或内网: %q", u.Hostname())
	}
	if port := u.Port(); port != "" {
		n, perr := strconv.Atoi(port)
		if perr != nil || n <= 0 || n > 65535 {
			return fmt.Errorf("下载地址端口非法: %q", port)
		}
		if n != 80 && n != 443 {
			return fmt.Errorf("下载地址端口不在白名单: %d", n)
		}
	}
	if strings.Contains(u.Path, "..") {
		return fmt.Errorf("下载地址路径包含上级引用")
	}
	return nil
}
