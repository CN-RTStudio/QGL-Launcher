package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func validateModDownloadURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("空的下载 URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("下载 URL 解析失败: %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("不安全的下载 URL（非 HTTPS）: scheme=%q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("下载 URL 不允许携带用户信息(userinfo): %s", u.Host)
	}
	if port := u.Port(); port != "" && port != "443" {
		return fmt.Errorf("下载 URL 只允许 443 端口，收到 %q", port)
	}
	if !modHostAllowed(u.Hostname()) {
		return fmt.Errorf("下载主机 %q 不在 Mod 下载白名单内", strings.ToLower(u.Hostname()))
	}
	return nil
}
func modDownloadCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return http.ErrUseLastResponse
	}
	next := req.URL
	if !isHTTPSURL(next.String()) {
		return errDenyInsecureRedirect
	}
	if isPrivateDest(next.String()) {
		return errDenyPrivateRedirect
	}
	if !modHostAllowed(next.Hostname()) {
		return fmt.Errorf("重定向到非白名单下载主机被拒绝: %s", strings.ToLower(next.Hostname()))
	}
	return nil
}
