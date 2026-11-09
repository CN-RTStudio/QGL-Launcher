package main

import (
	"net/url"
	"strings"
)

func verdictForHost(host string, resolve HostResolver) redirectVerdict {
	host = strings.TrimSpace(host)
	if host == "" {
		return verdictBlock("目标主机为空")
	}
	// 去掉 IPv6 括号与作用域，交给 parseDestIP 识别 IP 字面量。
	ip, isIP := parseDestIP(host)
	if isIP {
		if isPrivateOrLocalIP(ip) {
			return verdictBlock("目标解析到私网 / 回环 / 链路本地地址: " + host)
		}
		return verdictAllow()
	}
	if resolve == nil {
		return verdictBlock("无法解析目标主机（未配置解析器），宁严勿纵: " + host)
	}
	ips, err := resolve(host)
	if err != nil || len(ips) == 0 {
		return verdictBlock("目标主机解析失败，宁严勿纵: " + host)
	}
	for _, ip := range ips {
		if isPrivateOrLocalIP(ip) {
			return verdictBlock("目标主机解析到私网地址: " + host + " -> " + ip.String())
		}
	}
	return verdictAllow()
}
func guardRedirectTarget(rawURL string, resolve HostResolver) redirectVerdict {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return verdictBlock("目标 URL 无法解析主机")
	}
	if u.User != nil {
		return verdictBlock("目标 URL 不允许携带 userinfo")
	}
	return verdictForHost(u.Hostname(), resolve)
}
