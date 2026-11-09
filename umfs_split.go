package main

import (
	"context"
	"net"
	"net/http"
	"time"
)

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
