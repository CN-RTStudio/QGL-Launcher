package main

import (
	"fmt"
	"net"
)

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
