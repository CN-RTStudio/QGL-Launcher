package main

import (
	"crypto/tls"
	"net/http"
	"time"
)

func (e errText) Error() string { return string(e) }

// safeHTTPClient 创建安全的 HTTP 客户端：
//   - TLS 1.2+；
//   - 30 秒总超时（API JSON 够用，大文件走带 MaxBytesReader 的专用路径）；
//   - 跳转策略：只跟 https→https，且不跳内网。
func safeHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: safeCheckRedirect,
		Transport: &http.Transport{
			DialContext: safeDialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			// 单连接复用池上限别太大，避免在用户机器上占一堆 TIME_WAIT
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

// localHTTPClient 与 safeHTTPClient 相同，但不在 Dial 层拦截私网地址。
// 仅限用户主动配置的 Yggdrasil 外置登录服务器使用——本地调试皮肤站就是
// 跑在 127.0.0.1 / 局域网的 http 服务，这是用户显式指定的可信目标。
// 绝不能用于任何由远程元数据给出来的 URL。
func localHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: safeCheckRedirect,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}
