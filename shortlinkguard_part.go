package main

import (
	"fmt"
	"net/url"
	"strings"
)

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
