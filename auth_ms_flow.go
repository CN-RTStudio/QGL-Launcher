package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

func aesGCMDecrypt(encoded string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("密文太短")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

// 安全加固: 复用全局 safeHTTPClient（TLS 1.2+，30秒超时，Dial 层拦私网）
var httpClient = safeHTTPClient()

// yggHTTPClient 仅供用户主动配置的 Yggdrasil 外置登录使用：本地调试皮肤站
// 允许跑在 loopback/局域网，但绝不能用于远程元数据给出的 URL。
var yggHTTPClient = localHTTPClient()

// readAuthJSON 用 LimitReader 限制响应体大小后再读 JSON，
// 防止恶意服务器返回几个 GiB 数据把内存吃爆。
func readAuthJSON(resp *http.Response) ([]byte, error) {
	limited := io.LimitReader(resp.Body, authJSONMaxBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= authJSONMaxBytes {
		return nil, fmt.Errorf("响应体超过 %d 字节上限", authJSONMaxBytes)
	}
	return body, nil
}

// DeviceCodeResponse 设备代码响应
type DeviceCodeResponse struct {
	UserCode         string `json:"user_code"`
	DeviceCode       string `json:"device_code"`
	VerificationURL  string `json:"verification_uri"`
	ExpiresIn        int    `json:"expires_in"`
	Interval         int    `json:"interval"`
	Message          string `json:"message"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// TokenResponse 令牌响应
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// XBLAuthResponse Xbox Live 认证响应

type XBLAuthResponse struct {
	IssueInstant  string `json:"IssueInstant"`
	NotAfter      string `json:"NotAfter"`
	Token         string `json:"Token"`
	DisplayClaims struct {
		XUI []struct {
			UHS string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
}
type XSTSAuthResponse struct {
	IssueInstant  string `json:"IssueInstant"`
	NotAfter      string `json:"NotAfter"`
	Token         string `json:"Token"`
	DisplayClaims struct {
		XUI []struct {
			UHS string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
	ErrorCode int    `json:"XErr"`
	Message   string `json:"Message"`
}
type MCLoginResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Username    string `json:"username"`
	// 错误字段
	Error            string `json:"error"`
	ErrorMessage     string `json:"errorMessage"`
	DeveloperMessage string `json:"developerMessage"`
}
type MCProfileResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type MCEntitlementResponse struct {
	Items []struct {
		Name string `json:"name"`
	} `json:"items"`
}
