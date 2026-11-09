package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// maxRedirectHops 是展开短链时允许的最大跳转次数（含首次请求）。
const maxRedirectHops = 3

// shortenerHosts 是启动器可能遇到的知名短链服务主机表（去 www. 前缀后匹配）。
// 名单外的主机不享受“短链”特殊通道，但仍会被下面的协议 / 私网规则拦截。
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

// HostResolver 把主机名解析成 IP 列表；nil 表示“无法解析”（保守拒绝）。
type HostResolver func(host string) ([]net.IP, error)

// knownShortenerHost 判断主机名是否属于已知短链服务。
// 末尾的点（`bit.ly.` 这种 FQDN 写法）不改变真实主机，先剥掉再查表，否则
// 攻击者只要在域名后补一个点就能跳过整条短链预检。
func knownShortenerHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimPrefix(h, "www.")
	h = strings.TrimRight(h, ".")
	if h == "" {
		return false
	}
	return shortenerHosts[h]
}

// isShortLinkURL 报告 rawURL 是否解析自短链服务（解析失败返回 false）。
// 用 Hostname() 取主机：u.Host 里带着端口（`bit.ly:443`）与 IPv6 括号，
// 直接拿它查表会把「短链 + 显式端口」判成普通 URL，从而跳过目标私网判定。
func isShortLinkURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	return knownShortenerHost(u.Hostname())
}

// redirectVerdict 是一次展开预检的结论。
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

// verdictForHost 判定单个主机名是否安全（IP 字面量直接判定，域名走 resolver）。
