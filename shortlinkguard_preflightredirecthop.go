package main

import (
	"fmt"
	"net"
	"strings"
)

func preflightRedirectHop(targetURL string, hops int, resolve HostResolver) error {
	if hops > maxRedirectHops {
		return fmt.Errorf("重定向跳数超过上限 %d", maxRedirectHops)
	}
	norm, err := normalizeScheme(targetURL)
	if err != nil {
		return err
	}
	if v := guardRedirectTarget(norm, resolve); v.Blocked {
		return fmt.Errorf("重定向目标预检拒绝: %s", v.Reason)
	}
	return nil
}

// netLookupResolver 是 App 层可注入的真实解析器（net.LookupIP）。
func netLookupResolver(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// preflightDownloadURL 是 secure_download 接线入口：任何下载 URL 出发前先过
// 短链预检。非短链 URL 只做协议 / userinfo 校验，开销极小；短链 URL 追加
// 主机私网判定。resolve 为空时使用 net.LookupIP（会真实发 DNS，仅域名场景）。
func preflightDownloadURL(rawURL string, resolve HostResolver) (string, error) {
	if resolve == nil {
		resolve = netLookupResolver
	}
	return preflightShortLink(rawURL, 0, resolve)
}

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
