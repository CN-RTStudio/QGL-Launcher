package main

import (
	"context"
	"io"
	"net/http"
	"os/exec"
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

// ServerConfig 服务器配置
type ServerConfig struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Port       int    `json:"port"`
	MaxMemory  int    `json:"maxMemory"`
	MinMemory  int    `json:"minMemory"`
	OnlineMode bool   `json:"onlineMode"`
	ServerDir  string `json:"serverDir"`
}

// ServerStatus 服务器运行状态
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

func isValidMemory(mem int) bool {
	return mem >= minMemoryMB && mem <= maxMemoryMB
}

// IsServerPortAvailable 供前端在创建 / 修改服务器时实时探测端口是否空闲，
// 返回综合可用性与面向用户的中文原因。
func (a *App) IsServerPortAvailable(port int) map[string]interface{} {
	res := IsTCPPortAvailable(port)
	return map[string]interface{}{
		"free":   res.Free,
		"reason": res.Reason,
		"detail": describePortProbeReason(res.Reason),
	}
}

// safeGet 带超时和大小限制的 GET 封装。
//   - ctx 用 context.WithTimeout 包一层，防止对端挂死连接；
//   - maxBytes > 0 时用 http.MaxBytesReader 包 response body，
//     防止服务端返回超大 body 把内存/磁盘打爆。
func safeGet(client *http.Client, url string, maxBytes int64) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// 严格 match Chrome 版本号，但括号里全是大实话
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if maxBytes > 0 {
		resp.Body = http.MaxBytesReader(nil, resp.Body, maxBytes)
	}
	return resp, nil
}

// sanitizeServerName 清理服务器名称，防止路径遍历和特殊字符注入。
// 除历史上的 NewReplacer 删除路径分隔符 / properties 分隔符 / CR/LF 外，再兜底：
//   - 剩余任何 ASCII 控制字节（NUL/Tab/ESC 等）一律按非法名拒绝（返回空串）；
//   - 长度超过 maxServerNameLen 拒绝。名称随后会进目录名与 server.properties 的 motd，
//     不能无限长，也不能夹带终端转义 / NUL 截断。
