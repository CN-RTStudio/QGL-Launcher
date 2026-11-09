package main

import (
	"fmt"
	"net"
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

// guardRedirectTarget 对展开后的目标 URL 做完整预检；rawURL 已通过协议校验。
// 交给解析器的是 Hostname()：带上端口（`t.cn:443`）的 authority 不是主机名，
// 直接解析会失败并被当成「不可解析域名」拒绝，把合法目标误杀。
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

// preflightShortLink 是短链场景的完整预检：
//  1. 协议白名单（https 且无 userinfo）；
//  2. 目标主机私网判定；
//  3. 跳转次数预算。
//
// 返回规范化后的原始 URL（未展开，展开仍由下载器跟随重定向，但每跳都会
// 经过 Guard 校验；此处先拦住“第一跳”）。
func preflightShortLink(rawURL string, hops int, resolve HostResolver) (string, error) {
	if hops < 0 || hops > maxRedirectHops {
		return "", fmt.Errorf("重定向跳数超过上限 %d", maxRedirectHops)
	}
	norm, err := normalizeScheme(rawURL)
	if err != nil {
		return "", err
	}
	if !isShortLinkURL(norm) {
		// 非短链的普通 https 公网 URL 不额外折腾（私网拦截在 netaddrguard /
		// 下载器既有防线里处理），这里只保证协议与 userinfo 合规。
		return norm, nil
	}
	if v := guardRedirectTarget(norm, resolve); v.Blocked {
		return "", fmt.Errorf("短链目标预检拒绝: %s", v.Reason)
	}
	return norm, nil
}

// preflightRedirectHop 校验重定向链上的一跳（跟随 Location 前调用）：
// 目标必须是 https 公网且不指向私网；hops 为该跳序号（从 1 开始）。
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
