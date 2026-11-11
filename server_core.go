package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	minPort         = 1
	maxPort         = 65535
	minMemoryMB     = 128
	maxMemoryMB     = 32768
	allowedDirPerm  = 0700
	allowedFilePerm = 0600
	// maxServerJarBytes 限制服务端 JAR 最大 2GB，防止畸形 Content-Length 把磁盘打爆。
	// Mojang 官方服务端目前最大也就 ~70MB，2GB 留足余量。
	maxServerJarBytes = 2 << 30
	// httpTimeout 所有对 Mojang / BMCLAPI 的 HTTP 调用统一 5 分钟超时，避免卡死。
	httpTimeout = 5 * time.Minute
	// maxServerLogLineBytes 单行服务端日志的读取上限（堆栈 / JSON 单行也不会超过此值）。
	maxServerLogLineBytes = 1 << 20 // 1 MiB
	// userAgent 一个"严格 match Chrome 版本号、但括号里全是大实话"的 UA：
	//   - AppleWebKit/537.36、Chrome/131.0.0.0、Safari/537.36 三个关键 token 原样保留，
	//     让 CDN 上那种 `Chrome\/(\d+)` 的 UA 嗅探照样命中；
	//   - 中间插一句大实话，谁抓包谁笑。
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Yeah right; is OpenQGL/1.0 (not like Gecko;not Safari/537.36;not AppleWebKit/537.36)"
)

type ServerConfig struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Port       int    `json:"port"`
	MaxMemory  int    `json:"maxMemory"`
	MinMemory  int    `json:"minMemory"`
	OnlineMode bool   `json:"onlineMode"`
	ServerDir  string `json:"serverDir"`
}

type ServerStatus struct {
	Running bool   `json:"running"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
	Ready   bool   `json:"ready"`
}

// ServerManager 服务器管理器
type ServerManager struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	status    ServerStatus
	logBuffer []string
	ctx       context.Context
	readyCh   chan struct{}
}

var serverMgr ServerManager

func isValidPort(port int) bool {
	return port >= minPort && port <= maxPort
}

func sanitizeServerName(name string) string {
	name = strings.TrimSpace(name)
	replacer := strings.NewReplacer(
		"..", "", "/", "", "\\", "", ":", "", "*", "", "?", "",
		"\"", "", "<", "", ">", "", "|", "", "\n", "", "\r", "",
	)
	name = replacer.Replace(name)
	if name == "" {
		return ""
	}
	if containsControlByte(name) {
		return ""
	}
	// 默认流程会用 name 直接做服务器目录名：拒绝 Windows 保留设备名（CON 等）与尾点，
	// 避免目录被导向设备或与已存在目录发生静默同名（Windows 会剥掉尾点）。
	if isReservedDeviceName(stemOfName(name)) {
		return ""
	}
	if strings.HasSuffix(name, ".") {
		return ""
	}
	if len(name) > maxServerNameLen {
		return ""
	}
	return name
}
func isPathTraversal(baseDir, targetPath string) bool {
	resolvedBase, err := filepath.Abs(baseDir)
	if err != nil {
		return true
	}
	resolvedTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return true
	}
	return !strings.HasPrefix(resolvedTarget, resolvedBase+string(os.PathSeparator)) && resolvedTarget != resolvedBase
}

func isStrictSubdir(base, target string) bool {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	// 拒绝直接对盘符 / 卷根动手，避免误删整盘。
	if strings.TrimRight(targetAbs, string(os.PathSeparator)) == filepath.VolumeName(targetAbs) {
		return false
	}
	// 尽量解析到真实路径，挫败“服务器目录是指向根目录 / 其外部的符号链接”。
	if real, err := filepath.EvalSymlinks(targetAbs); err == nil {
		targetAbs = real
	}
	if realBase, err := filepath.EvalSymlinks(baseAbs); err == nil {
		baseAbs = realBase
	}
	if targetAbs == baseAbs {
		return false
	}
	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	return true
}
