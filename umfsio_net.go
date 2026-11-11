package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

func isPrivateDest(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if host == "" {
		return true
	}
	if isLoopbackHostName(host) {
		return true
	}
	// 用更宽的 IP 字面量解析器，连十六进制/八进制/扁平整数/IPv4-mapped
	// IPv6 等非规范写法一并在字符串态识别，防止绕过内网拦截。
	if ip, ok := parseDestIP(host); ok {
		return isBlockedIP(ip)
	}
	// 没解析成 IP 字面量的（域名），交给 DNS，不在这里拦；
	// 真正解析到内网的边缘情况由 net.Dialer 侧再兜一次。
	return false
}

// isBlockedIP 报告 IP 是否属于不该被启动器主动连出的地址段。判定表统一收敛到
// ipparse.go 的 isNonPublicIP，与浏览器打开 / 短链 / 重定向共用同一份最严策略，
// 覆盖回环、RFC1918 私网、CGNAT、链路本地（含云元数据 169.254.169.254）、未指定、
// 0.0.0.0/8 “本网络”段，以及此前漏掉的整段 224/4 多播（如 SSDP 239.255.255.250）
// 与 240/4 保留段（含 255.255.255.255 有限广播）。
func isBlockedIP(ip net.IP) bool {
	return isNonPublicIP(ip)
}

func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// 主机本身就是 IP 字面量时（含非规范进制 / IPv4-mapped 写法），直接按
	// 规范化地址判定并建连，不再交给 resolver：不同平台 resolver 对
	// "2130706433"、"0x7f.1" 这类写法行为不一致，先归一化可彻底消除歧义。
	if ip, ok := parseDestIP(host); ok {
		if isBlockedIP(ip) {
			return nil, errDenyPrivateRedirect
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, a := range addrs {
		if isBlockedIP(a.IP) {
			lastErr = errDenyPrivateRedirect
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errDenyPrivateRedirect
	}
	return nil, lastErr
}
func safeCheckRedirect(requ *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return http.ErrUseLastResponse
	}
	next := requ.URL
	if !isHTTPSURL(next.String()) {
		return errDenyInsecureRedirect
	}
	if isPrivateDest(next.String()) {
		return errDenyPrivateRedirect
	}
	return nil
}

var (
	errDenyInsecureRedirect = &url.Error{Op: "Get", URL: "", Err: errText("redirect to non-HTTPS blocked")}
	errDenyPrivateRedirect  = &url.Error{Op: "Get", URL: "", Err: errText("redirect to private/loopback address blocked")}
)

type errText string

func (e errText) Error() string { return string(e) }

// safeHTTPClient 创建安全的 HTTP 客户端：
//   - TLS 1.2+；
//   - 30 秒总超时（API JSON 够用，大文件走带 MaxBytesReader 的专用路径）；
//   - 跳转策略：只跟 https→https，且不跳内网。
func safeHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: safeCheckRedirect,
		Transport: &http.Transport{
			DialContext: safeDialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			// 单连接复用池上限别太大，避免在用户机器上占一堆 TIME_WAIT
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

// localHTTPClient 与 safeHTTPClient 相同，但不在 Dial 层拦截私网地址。
// 仅限用户主动配置的 Yggdrasil 外置登录服务器使用——本地调试皮肤站就是
// 跑在 127.0.0.1 / 局域网的 http 服务，这是用户显式指定的可信目标。
// 绝不能用于任何由远程元数据给出来的 URL。
func localHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: safeCheckRedirect,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}
