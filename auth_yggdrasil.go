package main

import (
	"fmt"
	"net/url"
	"strings"
)

// ===== Yggdrasil 外置登录 =====

type YggdrasilAuthResponse struct {
	AccessToken       string `json:"accessToken"`
	ClientToken       string `json:"clientToken"`
	AvailableProfiles []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"availableProfiles"`
	SelectedProfile *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"selectedProfile"`
	Error        string `json:"error"`
	ErrorMessage string `json:"errorMessage"`
	Cause        string `json:"cause"`
}

type YggdrasilServerMeta struct {
	ServerName string `json:"serverName"`
}

type YggdrasilServerLinks struct {
	Homepage string `json:"homepage"`
	Register string `json:"register"`
}

type YggdrasilServerInfo struct {
	Meta  YggdrasilServerMeta  `json:"meta"`
	Links YggdrasilServerLinks `json:"links"`
}

// isLoopbackOrPrivateHost 判断 host 是否为回环/私网地址。
//
// 地址解析统一借 parseDestIP：除规范四段 / IPv6 外，还识别 127.1、2130706433、
// 0x7f000001、017700000001 等 inet_aton 短格式 / 进制混淆（历史上这里只调 net.ParseIP，
// 本地调试皮肤站写成 http://127.1 时会被误当公网而拒绝明文 HTTP）。允许范围刻意不变，
// 仍是回环 / RFC1918 私网 / 链路本地，不扩大到 CGNAT、0/8、多播等其它保留段。
func isLoopbackOrPrivateHost(host string) bool {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip, ok := parseDestIP(host); ok {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return false
}

// normalizeYggdrasilURL 规范化 Yggdrasil 服务器地址
//
// 安全要求：默认强制 HTTPS，因为 LoginYggdrasil 会明文 POST 用户密码。
// 仅当 host 是回环/私网（127.x / 10.x / 192.168.x / 172.16-31.x / ::1）时
// 才允许 http://，用于本地调试皮肤站。
//
// 历史 bug 修复：之前判断写成 `u.Scheme == "http://"`，而 url.Parse 给的 Scheme
// 永远是不带冒号斜杠的 "http"，导致该判断恒为 false——私网 http 调试也被错误拒绝。
// 现在按 u.Scheme == "http" 判断。
func normalizeYggdrasilURL(serverURL string) (string, error) {
	// 任何 ASCII 控制字符（含 CR/LF/Tab/NUL）都拒绝，且必须在 TrimSpace 之前检查：
	// 该地址随后会被拼进密码 POST 请求行，混入换行可能被截断、按后半段重解释。
	// 先剥空白再查会让用户输入里“尾随的换行 / 制表符”被静默吞掉——对认证地址这类
	// 高风险输入，选择显式拒绝而非悄悄归一化，便于前端提示用户修正。
	for i := 0; i < len(serverURL); i++ {
		if serverURL[i] < 0x20 || serverURL[i] == 0x7f {
			return "", fmt.Errorf("服务器地址含不可见控制字符，已拒绝")
		}
	}
	serverURL = strings.TrimSpace(serverURL)

	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		return "", fmt.Errorf("无效的服务器地址协议，只支持 http/https")
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("无法解析服务器地址: %v", err)
	}
	// 拒绝 userinfo 视觉混淆：https://trusted.example@evil.test/api/yggdrasil 用户看到
	// 的是 trusted，但密码实际发往 evil，必须在 POST 密码前拦下。
	if u.User != nil {
		return "", fmt.Errorf("服务器地址不允许携带用户名/密码(userinfo)，请去掉 @ 前的内容")
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("服务器地址缺少主机名")
	}
	if u.Scheme == "http" && !isLoopbackOrPrivateHost(u.Hostname()) {
		return "", fmt.Errorf("禁止通过明文 HTTP 连接公网 Yggdrasil 服务器（密码会被窃听），请使用 https://")
	}

	// 剥掉全部结尾斜杠（而不是只剥一个），避免 "…/api/yggdrasil//" 这类地址
	// 因单次 TrimSuffix 失配而被再次追加成 "…/api/yggdrasil//api/yggdrasil"。
	for strings.HasSuffix(serverURL, "/") {
		serverURL = strings.TrimSuffix(serverURL, "/")
	}
	if !strings.HasSuffix(serverURL, "/api/yggdrasil") {
		serverURL = serverURL + "/api/yggdrasil"
	}
	return serverURL, nil
}
