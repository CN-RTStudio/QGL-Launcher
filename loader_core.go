package main

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func isHTTPSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Scheme == "https"
}

var allowedMavenLibHosts = map[string]bool{
	"maven.minecraftforge.net": true,
	"maven.neoforged.net":      true,
	"libraries.minecraft.net":  true,
	"piston-data.mojang.com":   true,
	"maven.fabricmc.net":       true,
	"repo1.maven.org":          true, // Maven Central，部分安装器依赖在此
	"bmclapi2.bangbang93.com":  true, // BMCLAPI 镜像（重写后的目标主机）
}

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
func readLimited(r io.Reader, maxSize int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxSize))
}

const apiJSONMaxBytes = 10 << 20

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

var forgeInstallerJar []byte

// ===== 模组加载器相关结构体 =====

type LoaderInfo struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Version      string `json:"version"`
	MCVersion    string `json:"mcVersion"`
	DownloadURL  string `json:"downloadUrl"`
	IsInstalled  bool   `json:"isInstalled"`
	Stable       bool   `json:"stable"`
	Category     string `json:"category"`
	ForgeVersion string `json:"forgeVersion"`
	IsPreview    bool   `json:"isPreview"`
	Patch        string `json:"patch"`
	OptiFineType string `json:"optifineType"`
}

type BMCLAPIForgeEntry struct {
	Branch   string `json:"branch"`
	Modified string `json:"modified"`
	Version  string `json:"version"`
	Files    []struct {
		Category string `json:"category"`
		Format   string `json:"format"`
		Hash     string `json:"hash"`
		ID       int    `json:"id"`
		Size     int64  `json:"size"`
	} `json:"files"`
}

type BMCLAPIOptiFineEntry struct {
	MCVersion string `json:"mcversion"`
	Type      string `json:"type"`
	Patch     string `json:"patch"`
	Filename  string `json:"filename"`
	Forge     string `json:"forge"`
}

type FabricLoaderVersion struct {
	Separator string `json:"separator"`
	Build     int    `json:"build"`
	Version   string `json:"version"`
	Maven     string `json:"maven"`
	Stable    bool   `json:"stable"`
}

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

const (
	maxInstallerJSONBytes int64 = 16 << 20  // 安装器内 JSON 元数据 16 MiB
	maxInstallerLibBytes  int64 = 256 << 20 // 安装器内内嵌库 jar 256 MiB
)

func isSafeRelPath(relPath string) string {
	if relPath == "" {
		return ""
	}
	cleaned := filepath.Clean(relPath)
	// 拒绝绝对路径
	if filepath.IsAbs(cleaned) {
		return ""
	}
	// 拒绝以 .. 开头的逃逸路径
	if strings.HasPrefix(cleaned, "..") {
		return ""
	}
	// 拒绝包含 .. 段的路径
	parts := strings.Split(cleaned, string(os.PathSeparator))
	for _, p := range parts {
		if p == ".." {
			return ""
		}
	}
	return cleaned
}
func (a *App) writeLog(format string, args ...interface{}) {
	// 在写控制台 / qgl_install.log / 启动日志之前统一脱敏：启动参数与游戏输出里
	// 可能带微软 access token、Bearer、JWT、密码等，任何一处落盘/外发都算泄密。
	msg := sanitizeLogLine(fmt.Sprintf(format, args...))
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, msg)

	fmt.Print(logLine)

	mcDir := a.GetMinecraftDir()
	logPath := filepath.Join(mcDir, "qgl_install.log")
	// 有界日志：4MiB 软上限 + 单份 .1 轮转 + 拒符号链接，防止崩溃循环刷屏占满磁盘。
	_ = getBoundedLogger(logPath).appendBounded(logLine)

	if a.launchLogPath != "" {
		dir := filepath.Dir(a.launchLogPath)
		// 日志目录同样收权到 0700（已存在的宽权限目录一并收敛），失败则放弃本次日志落盘。
		if ensurePrivateDir(dir) == nil {
			_ = getBoundedLogger(a.launchLogPath).appendBounded(logLine)
		}
	}
}
