package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

// safeDialContext 在 TCP 建连前再做一次 IP 级拦截。
// isPrivateDest 只能拦字符串形态的内网地址；公网域名通过自托管 DNS 解析到
// 127.0.0.1 / 169.254.169.254（DNS rebinding）时字符串看不出来，必须在这里兜：
// 先自行解析、逐个候选 IP 校验，全部非法则拒绝建连。
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

// safeCheckRedirect 是 http.Client.CheckRedirect 的实现：
//   - 只允许跳 https://（除非原地 http→http，且我们本来就只发 https）；
//   - 拒绝跳内网/回环/链路本地；
//   - 最多 maxRedirects 次。
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
