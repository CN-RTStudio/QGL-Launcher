package main

// redirchain.go —— HTTP 重定向链的逐跳安全决策内核。
//
// 与 shortlinkguard 的分工：shortlinkguard 在“发起请求之前”对一个已知 URL
// 做静态签证；本模块在下载器实际收到 3xx 响应、准备跟随 Location 时逐跳
// 决策（等价于 net/http.Client.CheckRedirect 的安全内核），解决只有进入
// 跳转链之后才暴露的问题：
//
//   - 协议降级：首跳 https，中途被引到 http://，明文链路可被改写后续目标；
//   - 协议逃逸：Location 指到 file:/javascript:/data:/vbscript: 等非传输协议；
//   - 跳转环：A→B→A 或自指 Location，造成无限请求（DoS / 流量放大）；
//   - userinfo 视觉混淆：https://trusted.com@evil.com/；
//   - 跨主机突变：白名单主机一跳转到攻击者主机再做 SSRF；
//   - DNS 重绑定：同一主机名在链中两次解析得到不同地址集，第一次通过
//     私网检查、第二次解析到 127.0.0.1（解析结果由调用方注入，本模块
//     只做集合比对，不发起网络请求）。
//
// 纯函数 + 注入式 resolver，全部判定可穷举测试。

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// RedirectLimits 重定向链的量化边界。
type RedirectLimits struct {
	MaxHops       int
	AllowDropToHTTP bool
	AllowCrossHost  bool
}

func defaultRedirectLimits() RedirectLimits {
	return RedirectLimits{
		MaxHops:         5,
		AllowDropToHTTP: false,
		AllowCrossHost:  true,
	}
}

// redirectChain 记录一次下载已经走过的跳转状态。
type redirectChain struct {
	links     []string
	seen      map[string]bool
	schemes   map[string]bool
	hostIPs   map[string][]net.IP
	firstHost string
	limits    RedirectLimits
}

// newRedirectChain 以入口 URL 初始化链；入口本身的合法性由调用方先过
// shortlinkguard，这里只做结构化记录。
func newRedirectChain(entry string, lim RedirectLimits) (*redirectChain, error) {
	if lim.MaxHops <= 0 {
		lim = defaultRedirectLimits()
	}
	u, err := url.Parse(strings.TrimSpace(entry))
	if err != nil {
		return nil, fmt.Errorf("redirect-chain: bad entry url: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	c := &redirectChain{
		seen:      map[string]bool{},
		schemes:   map[string]bool{},
		hostIPs:   map[string][]net.IP{},
		firstHost: host,
		limits:    lim,
	}
	c.schemes[strings.ToLower(u.Scheme)] = true
	c.seen[normalizeRedirectURL(u)] = true
	c.links = append(c.links, u.String())
	return c, nil
}

// Decide 对下一跳 Location 做安全裁决。allow=false 时 reason 给出拒绝原因。
// resolveIP 可为 nil：此时只做 IP 字面量与语法层检查，不做域名解析比对。
func (c *redirectChain) Decide(location string, resolveIP HostResolver) (allow bool, reason string) {
	if len(c.links) >= c.limits.MaxHops {
		return false, "too-many-hops"
	}
	loc := strings.TrimSpace(location)
	if loc == "" {
		return false, "empty-location"
	}
	prev, err := url.Parse(c.links[len(c.links)-1])
	if err != nil {
		return false, "bad-prev-url"
	}
	next, err := resolveLocation(prev, loc)
	if err != nil {
		return false, "bad-location-url"
	}

	scheme := strings.ToLower(next.Scheme)
	if scheme != "http" && scheme != "https" {
		return false, "non-http-scheme"
	}
	// 只有在链路里已经出现过 https 之后又落回 http，才算危险降级；入口本身就是
	// http（且 AllowDropToHTTP 关闭）时，http→http 同协议延续不应被误判为降级。
	if scheme == "http" && !c.limits.AllowDropToHTTP && c.schemes["https"] {
		return false, "downgrade-to-http"
	}
	if next.User != nil {
		return false, "userinfo-not-allowed"
	}
	host := strings.ToLower(next.Hostname())
	if host == "" {
		return false, "empty-host"
	}

	// 环检测：规范化后完全重复的 URL 直接拒绝。
	key := normalizeRedirectURL(next)
	if c.seen[key] {
		return false, "redirect-loop"
	}

	// 字面量 IP：用与出向拨号同一套宽解析器 parseDestIP 识别，连十进制整数 /
	// 十六进制 / 八进制 / IPv4-mapped 等混淆写法一并拦截，避免 2130706433 这类
	// 形态躲过私网判定形成 SSRF。
	ip, isIPLiteral := parseDestIP(host)
	if isIPLiteral && isPrivateOrLocalIP(ip) {
		return false, "host-not-public"
	}

	// 跨主机策略：默认允许跨主机（下载场景 CDN 切换常见），但收紧模式下
	// 只允许同注册域后缀；无论哪种模式，每跳主机都要过私网检查。
	if !c.limits.AllowCrossHost && !sameRegistrable(host, c.firstHost) {
		return false, "cross-host-denied"
	}

	if resolveIP != nil && !isIPLiteral {
		ips, err := resolveIP(host)
		if err != nil || len(ips) == 0 {
			return false, "dns-resolve-failed"
		}
		// DNS 重绑定优先判定：同主机名前后解析到的地址集不一致即拒绝，
		// 即便第二次恰好也是私网（127.0.0.1）也要报成 dns-rebinding。
		if prevIPs, ok := c.hostIPs[host]; ok && !ipSetEqual(prevIPs, ips) {
			return false, "dns-rebinding"
		}
		for _, ip := range ips {
			if isPrivateOrLocalIP(ip) {
				return false, "host-not-public"
			}
		}
		c.hostIPs[host] = ips
	}

	c.seen[key] = true
	c.schemes[scheme] = true
	c.links = append(c.links, next.String())
	return true, ""
}

// Hops 返回已记录的链接数（含入口）。
func (c *redirectChain) Hops() int { return len(c.links) }

// Links 返回链快照，调用方只读使用。
func (c *redirectChain) Links() []string {
	out := make([]string, len(c.links))
	copy(out, c.links)
	return out
}

// resolveLocation 解析 Location，支持绝对 URL、协议相对（//host/path）
// 与路径相对（/path、path、?query）三种形式。
func resolveLocation(base *url.URL, location string) (*url.URL, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(location, "://") && !strings.HasPrefix(location, "//") {
		u = base.ResolveReference(u)
		return u, nil
	}
	// 协议相对地址（//host/path）本身不带 scheme，必须沿用上一跳协议，
	// 否则会被当成空 scheme 误判为 non-http-scheme。
	if strings.HasPrefix(location, "//") && u.Scheme == "" {
		u.Scheme = base.Scheme
	}
	return u, nil
}

// normalizeRedirectURL 产出用于环检测的规范键：小写 scheme/host，去默认
// 端口，去 fragment，路径末尾斜杠归一。
func normalizeRedirectURL(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = host + ":" + port
	}
	path := strings.TrimSuffix(u.Path, "/")
	return scheme + "://" + host + path + "?" + u.RawQuery
}

// sameRegistrable 粗略同注册域判定：主机相等，或主机以点 + 基准结尾。
// 不做公共后缀表（启动器下载域均为自有/CDN 域，粗粒度足够且零依赖）。
func sameRegistrable(host, base string) bool {
	if base == "" {
		return false
	}
	return host == base || strings.HasSuffix(host, "."+base)
}

// ipSetEqual 比较两个 IP 集合是否一致（顺序无关）。
func ipSetEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, ip := range a {
		m[ip.String()]++
	}
	for _, ip := range b {
		k := ip.String()
		if m[k] == 0 {
			return false
		}
		m[k]--
	}
	return true
}
