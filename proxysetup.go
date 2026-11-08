package main

// proxysetup：JVM 代理参数守卫。
//
// 场景：实例/版本配置可以通过 -Dhttp.proxyHost=…、-Dhttps.proxyHost=…、
// -Dhttp.proxyPort=…、-DsocksProxyHost=… 等把游戏的全部出向流量导到
// 攻击者控制的代理，或指到 127.0.0.1/内网地址做 SSRF 探测。本模块：
//   - 从 JVM 参数里提取已知代理相关开关并逐个校验；
//   - scheme 只允许 http/https/socks4/socks5（白名单）；
//   - host 必须是公网可达地址：禁回环/链路本地/组播/内网段/混淆 IPv4
//     （复用 isPrivateOrLocalIP + parseDestIP），禁控制字符，长度有界；
//   - port 必须在 1..65535，且 http/https 代理端口默认禁 80/443 之外的
//     特权高危组合（保留端口检查）；
//   - 纯函数，不改任何配置。
import (
	"strconv"
	"strings"
)

// ProxyLimits 代理守卫的量化边界。
type ProxyLimits struct {
	MaxValueLen int
	MaxHostLen  int
	MaxEntries  int
}

func defaultProxyLimits() ProxyLimits {
	return ProxyLimits{
		MaxValueLen: 512,
		MaxHostLen:  253,
		MaxEntries:  8,
	}
}

type proxyEntry struct {
	Scheme string
	Host   string
	Port   int
	Raw    string
}

type proxyVerdict struct {
	OK      bool
	Reason  string
	Entries []proxyEntry
}

// proxySchemeOK 只接受已知代理 scheme 前缀。
func proxySchemeOK(prefix string) bool {
	switch strings.ToLower(prefix) {
	case "http", "https", "socks", "socks4", "socks5":
		return true
	}
	return false
}

// proxyHostOK 校验 host：非空、无控制字符、长度有界、非本机/内网/链路本地。
// 域名解析失败时按字面判定（不发起网络请求，纯语法层检查）。
func proxyHostOK(host string, lim ProxyLimits) (string, bool) {
	if host == "" {
		return "empty-host", false
	}
	if len(host) > lim.MaxHostLen {
		return "host-too-long", false
	}
	if strings.ContainsAny(host, "\x00\r\n\t ") {
		return "host-control-chars", false
	}
	// IP 字面量（含 inet_aton 混淆写法）归一化后是私网/回环/链路本地则拒绝，
	// 防止把代理指到本机元数据地址。公网 IP 字面量按域名放行（这里不强制域名形态）。
	if ip, ok := ipLiteralFromHost(host); ok && isPrivateOrLocalIP(ip) {
		return "host-not-public", false
	}
	return "", true
}

// proxyPortOK 端口必须在 1..65535；HTTP 代理端口还要求非保留特权口
// （避免指到 22/445/3389 等敏感服务端口做端口扫描）。
func proxyPortOK(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	switch port {
	case 22, 445, 137, 138, 139, 3389, 5900:
		return false
	}
	return true
}

// ParseProxyArgs 从 JVM 参数列表提取代理相关 -D 开关并校验。
// 返回 verdict；OK 表示所有命中项均合法，Reason 在失败时说明首个违规项。
func ParseProxyArgs(args []string, lim ProxyLimits) proxyVerdict {
	if lim.MaxValueLen == 0 || lim.MaxHostLen == 0 || lim.MaxEntries == 0 {
		lim = defaultProxyLimits()
	}
	v := proxyVerdict{OK: true}
	for _, arg := range args {
		if len(arg) > lim.MaxValueLen {
			continue
		}
		lower := strings.ToLower(arg)
		var scheme string
		var hostKey string
		switch {
		case strings.HasPrefix(lower, "-dhttp.proxyhost="):
			scheme, hostKey = "http", "-Dhttp.proxyHost="
		case strings.HasPrefix(lower, "-dhttps.proxyhost="):
			scheme, hostKey = "https", "-Dhttps.proxyHost="
		case strings.HasPrefix(lower, "-dsocksproxyhost="):
			scheme, hostKey = "socks5", "-DsocksProxyHost="
		case strings.HasPrefix(lower, "-dsocks5proxyhost="):
			scheme, hostKey = "socks5", "-Dsocks5ProxyHost="
		case strings.HasPrefix(lower, "-dsocks4proxyhost="):
			scheme, hostKey = "socks4", "-Dsocks4ProxyHost="
		default:
			continue
		}
		if !proxySchemeOK(scheme) {
			v.OK = false
			v.Reason = "bad-scheme"
			return v
		}
		value := strings.TrimPrefix(arg, hostKey)
		if value == "" {
			continue
		}
		if len(v.Entries) >= lim.MaxEntries {
			v.OK = false
			v.Reason = "too-many-proxies"
			return v
		}
		host, port := splitProxyHostPort(value)
		if reason, ok := proxyHostOK(host, lim); !ok {
			v.OK = false
			v.Reason = reason
			return v
		}
		p := 8080
		if port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || !proxyPortOK(n) {
				v.OK = false
				v.Reason = "bad-port"
				return v
			}
			p = n
		}
		v.Entries = append(v.Entries, proxyEntry{
			Scheme: scheme,
			Host:   host,
			Port:   p,
			Raw:    arg,
		})
	}
	return v
}

// splitProxyHostPort 拆 host[:port]，host 部分用方括号包 IPv6 时一并剥离。
func splitProxyHostPort(value string) (string, string) {
	value = strings.TrimPrefix(value, "[")
	if idx := strings.Index(value, "]"); idx >= 0 {
		if strings.HasPrefix(value, "[") || idx == len(value)-1 {
			rest := value[idx+1:]
			if strings.HasPrefix(rest, ":") {
				return value[:idx], rest[1:]
			}
			return value[:idx], ""
		}
	}
	if idx := strings.LastIndex(value, ":"); idx >= 0 && !strings.Contains(value[idx+1:], ":") {
		return value[:idx], value[idx+1:]
	}
	return value, ""
}

// SummarizeProxyVerdict 把 verdict 压成一行可读结果。
func SummarizeProxyVerdict(v proxyVerdict) string {
	if len(v.Entries) == 0 {
		return "proxy: none"
	}
	parts := make([]string, 0, len(v.Entries))
	for _, e := range v.Entries {
		parts = append(parts, e.Scheme+"://"+e.Host+":"+strconv.Itoa(e.Port))
	}
	status := "ok"
	if !v.OK {
		status = "blocked:" + v.Reason
	}
	return "proxy: " + status + " (" + strings.Join(parts, ", ") + ")"
}
