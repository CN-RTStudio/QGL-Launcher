package main

import (
	"net"
	"net/url"
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
