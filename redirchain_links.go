package main

import (
	"net/url"
	"strings"
)

func (c *redirectChain) Links() []string {
	out := make([]string, len(c.links))
	copy(out, c.links)
	return out
}
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
