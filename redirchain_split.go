package main

import (
	"net"
	"net/url"
	"strings"
)

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
