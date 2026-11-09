package main

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func readAPIJSON(resp *http.Response, v interface{}) error {
	body, err := readLimited(resp.Body, apiJSONMaxBytes)
	if err != nil {
		return err
	}
	if int64(len(body)) >= apiJSONMaxBytes {
		return fmt.Errorf("API 响应超过 %d 字节上限", apiJSONMaxBytes)
	}
	return json.Unmarshal(body, v)
}

// 安装器（Forge/NeoForge JAR）来自镜像、不受信任。其中的 install_profile.json /
// version.json 正常只有几百 KB，内嵌的库 jar 正常几十 MB。给条目读取设上限，
// 防止恶意安装器用高压缩比超大条目把进程内存撑爆（解压炸弹）。
const (
	maxInstallerJSONBytes int64 = 16 << 20  // 安装器内 JSON 元数据 16 MiB
	maxInstallerLibBytes  int64 = 256 << 20 // 安装器内内嵌库 jar 256 MiB
)

// readZipEntryLimited 读取单个 zip 条目并限制解压后体积：
// 先用 zip 元数据预检，再用 LimitReader 多读 1 字节判定实际超限，
// 调用方无需信任 f.UncompressedSize64 与真实流是否一致。
func readZipEntryLimited(f *zip.File, maxBytes int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(maxBytes) {
		return nil, fmt.Errorf("zip 条目解压后声明体积超过 %d 字节: %s", maxBytes, f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("zip 条目解压后体积超过 %d 字节: %s", maxBytes, f.Name)
	}
	return data, nil
}

// isSafeFileName 验证版本名/文件名只包含安全字符
// 防止路径遍历攻击（../, /, \ 等），只允许字母、数字、点、下划线、短横线
func isSafeFileName(name string) bool {
	if len(name) == 0 || len(name) > 100 {
		return false
	}
	for _, r := range name {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	// ASCII 白名单已经挡掉分隔符与冒号，但 CON / NUL / COM1 这类纯字母数字的
	// Windows 保留设备名仍能通过，统一复用 nameguard 的保留名判定再挡一道。
	if isReservedDeviceName(stemOfName(name)) {
		return false
	}
	return true
}
