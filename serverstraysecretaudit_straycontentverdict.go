package main

import (
	"bytes"
	"strings"
)

func strayContentVerdict(data []byte) (string, string, bool) {
	if len(data) == 0 {
		return "", "", false
	}
	if bytes.Contains(data, []byte("-----BEGIN")) &&
		(bytes.Contains(data, []byte("PRIVATE KEY-----")) || bytes.Contains(data, []byte("OPENSSH PRIVATE KEY-----")) ||
			bytes.Contains(data, []byte("RSA PRIVATE KEY-----")) || bytes.Contains(data, []byte("EC PRIVATE KEY-----"))) {
		return strayReasonPrivateKey, "文件内包含私钥块", true
	}
	lower := strings.ToLower(string(data))
	for _, key := range []string{
		"aws_secret_access_key",
		"aws_access_key_id",
		"azure_storage_key",
		"gcp_service_account",
		"private_key_id",
		"client_secret",
		"refresh_token",
		"discord_token",
		"bot_token",
	} {
		if strings.Contains(lower, key) {
			return strayReasonCloudSecret, "文件内包含云服务或机器人凭据字段", false
		}
	}
	for _, key := range []string{"password=", "passwd=", "api_key=", "apikey=", "secret=", "token="} {
		if strings.Contains(lower, key) {
			return strayReasonEnvSecret, "文件内包含键值形式凭据", false
		}
	}
	return "", "", false
}
