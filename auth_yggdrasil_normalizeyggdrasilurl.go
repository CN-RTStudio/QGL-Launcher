package main

import (
	"fmt"
	"net/url"
	"strings"
)

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
