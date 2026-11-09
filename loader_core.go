package main

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ===== 安全工具函数 =====

// isHTTPSURL 验证 URL 是否为 HTTPS 协议
// 防止 HTTP 中间人攻击，所有下载 URL 必须使用 HTTPS
func isHTTPSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Scheme == "https"
}

// allowedMavenLibHosts 是允许下载游戏依赖库的 Maven 主机白名单。
// install_profile.json / version.json 来自镜像上不受信任的安装器，其中每个库
// 的 url/sha1 都由安装器作者填写：攻击者可以把某个库的 url 指向自己的服务器，
// 该 jar 最终会落进 libraries 并进入 JVM classpath，等同于远程代码执行。
// 光有 https 和“随安装器自带的 sha1”挡不住这一点（主机和 sha1 都是攻击者写的），
// 所以必须把下载主机限定在官方/可信 Maven 源，再尽量用官方 sha1 复核传输完整性。
var allowedMavenLibHosts = map[string]bool{
	"maven.minecraftforge.net": true,
	"maven.neoforged.net":      true,
	"libraries.minecraft.net":  true,
	"piston-data.mojang.com":   true,
	"maven.fabricmc.net":       true,
	"repo1.maven.org":          true, // Maven Central，部分安装器依赖在此
	"bmclapi2.bangbang93.com":  true, // BMCLAPI 镜像（重写后的目标主机）
}

// isAllowedMavenLibURL 判断依赖库下载 URL 是否落在可信 Maven 主机上。
// 强制 https、不允许 userinfo、只允许默认 443、主机必须精确命中白名单
// （用 map 精确匹配而非后缀匹配，避免 evil-maven.minecraftforge.net.evil.com
// 之类的伪造主机绕过）。
func isAllowedMavenLibURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	if u.Scheme != "https" || u.User != nil {
		return false
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".") // 容忍结尾点，但仍须精确命中
	return allowedMavenLibHosts[host]
}

// readLimited 读取响应体，限制最大大小防止内存耗尽攻击
// 用于 API JSON 响应，最大 10MB
func readLimited(r io.Reader, maxSize int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxSize))
}

// apiJSONMaxBytes 限制所有元数据 API 返回的 JSON 响应大小。
// 版本清单 / Loader 列表等接口本应返回几 KB ~ 几百 KB，
// 超过 10 MiB 基本就是恶意响应或错误页面，直接拒绝。
const apiJSONMaxBytes = 10 << 20

// readAPIJSON 读 resp.Body 并在 10 MiB 上限内 Unmarshal。
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

// isSafeRelPath 验证相对路径不包含路径遍历组件（Zip Slip 防护）
// 返回清洗后的安全路径，如果不安全返回空字符串
