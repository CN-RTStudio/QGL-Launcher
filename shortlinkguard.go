package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

const maxRedirectHops = 3

var shortenerHosts = map[string]bool{
	"bit.ly":      true,
	"t.co":        true,
	"goo.gl":      true,
	"tinyurl.com": true,
	"is.gd":       true,
	"s.id":        true,
	"t.cn":        true,
	"dwz.cn":      true,
	"url.cn":      true,
	"u.nu":        true,
	"rb.gy":       true,
	"cutt.ly":     true,
	"shorte.st":   true,
	"suo.im":      true,
	"tiny.cc":     true,
	"shorturl.at": true,
	"v.gd":        true,
}

type HostResolver func(host string) ([]net.IP, error)

func knownShortenerHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimPrefix(h, "www.")
	h = strings.TrimRight(h, ".")
	if h == "" {
		return false
	}
	return shortenerHosts[h]
}
func isShortLinkURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	return knownShortenerHost(u.Hostname())
}

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

type redirectVerdict struct {
	Blocked  bool   // true 表示必须拒绝
	Reason   string // 拒绝原因（Blocked 时）
	Resolved bool   // 是否成功解析到目标 IP（域名场景）
}

// verdictAllow 构造放行结论。
func verdictAllow() redirectVerdict { return redirectVerdict{} }

// verdictBlock 构造拒绝结论。
func verdictBlock(reason string) redirectVerdict {
	return redirectVerdict{Blocked: true, Reason: reason}
}

// classifyURLProtocol 校验协议并拒绝非 http(s)。返回规范化 URL 或错误。
func normalizeScheme(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("URL 为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("URL 无法解析: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		// 保留原样（禁止 userinfo：防止 user:pass@host 借短链夹带凭据）。
		if u.User != nil {
			return "", fmt.Errorf("URL 不允许携带 userinfo")
		}
		// 下面三条是「结构完整性」：`https://`、`https://:443/x` 这类空主机串，
		// `https:opaque` 这种不透明形式，以及 `#fragment` 尾巴，都不会被真正的
		// HTTP 请求使用，却会让审计日志 / 落盘名看到与真实主机不同的内容。
		// 预检是出发前唯一一次能明确拒绝的地方，这里一律判死。
		if u.Opaque != "" {
			return "", fmt.Errorf("URL 不允许不透明（opaque）形式")
		}
		if u.Hostname() == "" {
			return "", fmt.Errorf("URL 缺少目标主机")
		}
		if u.Fragment != "" || u.RawFragment != "" {
			return "", fmt.Errorf("下载 URL 不允许携带 fragment")
		}
		// 百分号编码的主机名在 DNS 层会被再次解码，`%31%32%37.0.0.1` 之类
		// 写法在部分解析器上会还原成 127.0.0.1，直接拒绝整类编码主机。
		if strings.Contains(u.Host, "%") && !strings.HasPrefix(u.Host, "[") {
			return "", fmt.Errorf("URL 主机不允许百分号编码")
		}
		return u.String(), nil
	case "http":
		return "", fmt.Errorf("短链 / 重定向目标必须是 https，拒绝明文 http")
	case "file", "javascript", "data", "vbscript":
		return "", fmt.Errorf("拒绝协议 %s 的 URL", u.Scheme)
	default:
		return "", fmt.Errorf("不支持的协议: %s", u.Scheme)
	}
}
