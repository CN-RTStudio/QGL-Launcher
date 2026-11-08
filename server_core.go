package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// isPathTraversal 检查目标路径是否存在路径遍历风险
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

// isStrictSubdir 判断 target 是否为 base 的“严格子目录”：
// 解析符号链接后，target 既不能等于 base，也不能是 base 的父级或越出 base。
// 删除单个服务器时必须用它（而非 isPathTraversal），否则被篡改的 ServerDir
// 若等于服务器根目录，RemoveAll 会一次性清空所有服务器。
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

// GetServerDir 获取服务器根目录
func (a *App) GetServerDir() string {
	return filepath.Join(a.GetQGLDir(), "server")
}

// GetServerList 获取服务器列表
func (a *App) GetServerList() ([]ServerConfig, error) {
	serverDir := a.GetServerDir()
	if _, err := os.Stat(serverDir); os.IsNotExist(err) {
		return []ServerConfig{}, nil
	}
	entries, err := os.ReadDir(serverDir)
	if err != nil {
		return nil, err
	}
	var list []ServerConfig
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		configPath := filepath.Join(serverDir, entry.Name(), "QGL", "config.json")
		var cfg ServerConfig
		if err := readPrivateStoreJSON(configPath, &cfg, "服务器配置"); err != nil {
			continue
		}
		// 跳过任何被篡改 / 字段非法的配置，避免把带病条目暴露给前端和执行路径。
		if err := a.validateLoadedServerConfig(&cfg); err != nil {
			continue
		}
		list = append(list, cfg)
	}
	return list, nil
}

// CreateServer 创建服务器
func (a *App) CreateServer(name, version string, port, maxMem, minMem int, onlineMode bool, customDir string) error {
	name = sanitizeServerName(name)
	if name == "" {
		return fmt.Errorf("服务器名称不能为空")
	}
	if err := sanitizePathComponent(version); err != nil {
		return fmt.Errorf("无效的版本号: %v", err)
	}
	if !isValidPort(port) {
		return fmt.Errorf("端口号必须在 %d-%d 之间", minPort, maxPort)
	}
	if !isValidMemory(maxMem) || !isValidMemory(minMem) {
		return fmt.Errorf("内存必须在 %d-%d MB 之间", minMemoryMB, maxMemoryMB)
	}
	if minMem > maxMem {
		return fmt.Errorf("最小内存不能大于最大内存")
	}

	// 端口占用预检：在创建目录 / 下载 JAR 之前就发现端口冲突，避免用户一路配置完、
	// 启动时才在服务端日志里看到绑定失败。探测为咨询性（存在 TOCTOU 窗口），最终
	// 仍以 JVM 实际绑定为准；不受支持的协议族不算冲突。
	if probe := IsTCPPortAvailable(port); !probe.Free {
		return fmt.Errorf("端口 %d 无法使用：%s", port, describePortProbeReason(probe.Reason))
	}

	serverDir := a.GetServerDir()
	var dir string
	if customDir != "" {
		// 必须是绝对路径：否则 isPathTraversal 内部的 filepath.Abs 会按进程当前
		// 工作目录解析相对路径，判定基准随启动方式漂移，可能被绕过。
		if !filepath.IsAbs(customDir) {
			return fmt.Errorf("自定义目录必须是绝对路径")
		}
		customDir = filepath.Clean(customDir)
		if isPathTraversal(serverDir, customDir) {
			return fmt.Errorf("自定义目录路径不安全")
		}
		dir = customDir
	} else {
		dir = filepath.Join(serverDir, name)
	}

	if info, statErr := os.Lstat(dir); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("服务器目录不能是符号链接")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "QGL", "config.json")); statErr == nil {
		return fmt.Errorf("目录 %s 已存在服务器配置，拒绝覆盖", dir)
	}

	if err := os.MkdirAll(dir, allowedDirPerm); err != nil {
		return fmt.Errorf("创建服务器目录失败: %v", err)
	}

	qglDir := filepath.Join(dir, "QGL")
	if err := os.MkdirAll(qglDir, allowedDirPerm); err != nil {
		return fmt.Errorf("创建 QGL 配置目录失败: %v", err)
	}

	cfg := ServerConfig{
		Name:       name,
		Version:    version,
		Port:       port,
		MaxMemory:  maxMem,
		MinMemory:  minMem,
		OnlineMode: onlineMode,
		ServerDir:  dir,
	}
	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	// config.json 随后会进入 java -jar 执行路径，按敏感状态文件走原子私有写：
	// 防半截写、防预置符号链接写穿、强制 0600。
	if err := secureWritePrivateFile(filepath.Join(qglDir, "config.json"), cfgData); err != nil {
		return fmt.Errorf("保存配置失败: %v", err)
	}

	if err := a.downloadServerJar(version, dir); err != nil {
		return fmt.Errorf("下载服务器文件失败: %v", err)
	}

	eulaData := []byte("# By changing the setting below to TRUE you are indicating your agreement to our EULA (https://aka.ms/MinecraftEULA).\neula=true\n")
	if err := secureWriteFile(filepath.Join(dir, "eula.txt"), eulaData, allowedFilePerm); err != nil {
		return fmt.Errorf("创建 eula.txt 失败: %v", err)
	}

	// 初始 server.properties 走统一的安全读写器：键名 / 单行值 / motd 全部校验，
	// 原子写 .tmp 再 rename。旧实现 fmt.Sprintf 裸拼文本，motd 里的特殊语义字符
	// （前导空格、#、Tab、反斜杠等）没有经过 properties 值规则，存在配置注入不一致面。
	if err := writeInitialServerProperties(filepath.Join(dir, "server.properties"), port, onlineMode, name); err != nil {
		return fmt.Errorf("创建 server.properties 失败: %v", err)
	}

	return nil
}
