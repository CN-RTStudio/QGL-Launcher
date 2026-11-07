package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
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

// downloadServerJar 下载并校验服务器 JAR。
//
// 安全要点（服务端 JAR 随后会被 `java -jar` 执行，属于代码执行面）：
//   - 权威 SHA1 必须存在：Mojang 版本 JSON 的 downloads.server.sha1 缺失时，
//     绝不下载/运行来源不可校验的 JAR（旧逻辑在 sha1 缺失时会“裸奔”执行）；
//   - 已存在的 JAR 也要校验：旧逻辑只要文件在就直接复用，本地被替换/损坏、
//     或上次留下半截文件都会被原样执行。这里走与游戏库相同的侧车回退链
//     UMFS -> SHA512 -> 官方 SHA1，命中才复用，否则删除重下；
//   - 新下载落盘先写同目录 .tmp，用官方 SHA1 校验通过后才 rename 成正式 JAR，
//     随后补写 UMFS/SHA512 侧车。
func (a *App) downloadServerJar(version string, targetDir string) error {
	if err := sanitizePathComponent(version); err != nil {
		return fmt.Errorf("无效的版本号: %v", err)
	}
	jarPath := filepath.Join(targetDir, version+"-server.jar")

	jarURL, expectedHash, err := a.resolveServerJarDownload(version)
	if err != nil {
		return err
	}
	// 服务端 JAR 是要被执行的代码，缺少权威 SHA1 时一律拒绝，不能裸奔。
	expectedHash = strings.ToLower(strings.TrimSpace(expectedHash))
	if expectedHash == "" {
		return fmt.Errorf("版本 %s 的官方清单缺少服务端 SHA1，拒绝运行未校验的 JAR", version)
	}

	// 已有 JAR：必须通过侧车回退链 / 官方 SHA1 才允许复用，否则连同侧车一起删除重下。
	if info, statErr := os.Stat(jarPath); statErr == nil && info.Size() > 0 {
		if a.verifyCachedFile(jarPath, expectedHash) {
			return nil
		}
		_ = os.Remove(jarPath)
		removeCachedFileMeta(jarPath)
	}

	dlResp, err := safeGet(httpClient, jarURL, maxServerJarBytes)
	if err != nil {
		return fmt.Errorf("下载服务端 JAR 失败: %v", err)
	}
	defer dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载服务端 JAR 失败 (HTTP %d)", dlResp.StatusCode)
	}

	// 临时文件放在目标同目录，保证最后的 rename 是同卷原子操作；O_EXCL 避免跟随符号链接。
	tempPath := jarPath + ".tmp"
	if _, err := prepareTempPath(tempPath, time.Now(), staleTempMaxAge); err != nil {
		return fmt.Errorf("清理上次下载的临时文件失败: %v", err)
	}
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %v", err)
	}

	hasher := sha1.New()
	tee := io.TeeReader(dlResp.Body, hasher)
	if _, err := io.Copy(file, tee); err != nil {
		file.Close()
		os.Remove(tempPath)
		return fmt.Errorf("写入文件失败: %v", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("关闭临时文件失败: %v", err)
	}

	// 外部协议摘要（Mojang SHA1）保持原算法，是首次下载唯一的权威校验；不通过绝不 rename。
	if actualHash := hex.EncodeToString(hasher.Sum(nil)); actualHash != expectedHash {
		os.Remove(tempPath)
		removeCachedFileMeta(tempPath)
		return fmt.Errorf("服务端 JAR 哈希校验失败")
	}

	if err := os.Rename(tempPath, jarPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("重命名文件失败: %v", err)
	}

	// 官方 SHA1 已通过：补写本地 UMFS/SHA512 侧车，供下次启动快速且更强地校验。
	if err := a.saveCachedFileMeta(jarPath, expectedHash); err != nil {
		a.writeLog("服务端 JAR 侧车元数据写入失败（不影响完整性）: %s: %v", jarPath, err)
	}
	return nil
}

// resolveServerJarDownload 解析指定版本服务端 JAR 的最终下载地址与官方 SHA1。
// 地址已强制 https，并把 Mojang 主机替换为 BMCLAPI 镜像；SHA1 仍取官方清单，
// 镜像换源不改变信任锚。
func (a *App) resolveServerJarDownload(version string) (string, string, error) {
	manifest, err := a.GetVersionManifest()
	if err != nil {
		return "", "", fmt.Errorf("获取版本清单失败: %v", err)
	}
	var versionURL string
	for _, v := range manifest {
		if v.ID == version {
			versionURL = v.URL
			break
		}
	}
	if versionURL == "" {
		return "", "", fmt.Errorf("找不到版本 %s", version)
	}
	if !strings.HasPrefix(versionURL, "https://") {
		return "", "", fmt.Errorf("版本清单 URL 必须使用 HTTPS")
	}
	versionURL = rewriteMetaIndexURLToBMCL(versionURL)

	// 版本 JSON 很小，限制 8MB 足够
	resp, err := safeGet(httpClient, versionURL, 8<<20)
	if err != nil {
		return "", "", fmt.Errorf("下载版本 JSON 失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("下载版本 JSON 失败 (HTTP %d)", resp.StatusCode)
	}

	// safeGet 已用 MaxBytesReader 限制体积，但读体中途断连仍会留下截断字节，
	// 必须显式判错：否则会把半个 JSON 交给 Unmarshal，报成"解析失败"而掩盖真实
	// 的网络中断，也让调用方无法据此区分镜像故障与数据损坏。
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", "", fmt.Errorf("读取版本 JSON 响应体失败: %v", readErr)
	}
	var versionJSON map[string]interface{}
	if err := json.Unmarshal(body, &versionJSON); err != nil {
		return "", "", fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	downloads, ok := versionJSON["downloads"].(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("版本 JSON 中没有 downloads 字段")
	}
	server, ok := downloads["server"].(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("Mojang 没有为 %s 提供官方服务端下载", version)
	}
	jarURL, _ := server["url"].(string)
	if jarURL == "" {
		return "", "", fmt.Errorf("无法获取服务端下载地址")
	}
	if !strings.HasPrefix(jarURL, "https://") {
		return "", "", fmt.Errorf("服务端下载地址必须使用 HTTPS")
	}
	expectedHash, _ := server["sha1"].(string)

	jarURL = rewriteMappedDataURLToBMCL(jarURL)
	// 仅校验 https 前缀不足以防止恶意 / 被篡改的版本清单把 downloads.server.url
	// 指向任意主机：最终必须落在可信的 Mojang / BMCLAPI 主机白名单上（与依赖库同一
	// 套 isAllowedMavenLibURL 判定，强制 https、无 userinfo、443、主机精确命中）。
	if !isAllowedMavenLibURL(jarURL) {
		return "", "", fmt.Errorf("服务端下载地址不在可信主机白名单内")
	}
	return jarURL, expectedHash, nil
}

// StartServer 启动服务器
func (a *App) StartServer(name string) error {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	if serverMgr.status.Running {
		return fmt.Errorf("服务器已在运行中")
	}

	cfg, err := a.getServerConfig(name)
	if err != nil {
		return err
	}
	if isPathTraversal(a.GetServerDir(), cfg.ServerDir) {
		return fmt.Errorf("服务器目录路径不安全，拒绝启动")
	}

	// 启动目标审计：cfg.Version 由用户配置可控，直接拼 "<v>-server.jar" 时若版本名
	// 含分隔符 / ".." / 绝对前缀，-jar 会相对 cmd.Dir 解析到 ServerDir 之外的 jar
	// （=加载攻击者放置的类）。这里把工作目录、拼出的 jar 与内存边界统一收敛到
	// launchtarget 内核，critical 一律拒绝启动。
	serverRoot := a.GetServerDir()
	launchAudit := AuditServerLaunch(cfg.ServerDir, cfg.Version, cfg.MinMemory, cfg.MaxMemory, []string{serverRoot})
	if launchAudit.HasCritical() {
		return fmt.Errorf("服务器启动目标校验失败，拒绝启动: %s", launchAudit.FirstCriticalCode())
	}

	worldName, worldNameSet, worldNameErr := readWorldLevelName(cfg.ServerDir)
	if worldNameErr != nil {
		return worldNameErr
	}
	if worldNameSet {
		worldAudit, err := AuditWorldPath(cfg.ServerDir, worldName)
		if err != nil {
			return err
		}
		if worldAudit.Blocking() {
			recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
				describeWorldPathAudit(worldAudit), cfg.ServerDir)
			return fmt.Errorf("世界目录校验失败，拒绝启动: %s", describeWorldPathAudit(worldAudit))
		}
		if len(worldAudit.Warnings) > 0 {
			a.writeLog("世界目录告警: %s", strings.Join(worldAudit.Warnings, "；"))
		}
	}

	if worldNameSet {
		worldAudit, _ := AuditWorldPath(cfg.ServerDir, worldName)
		if worldAudit.Present && !worldAudit.Symlink {
			datapackAudit, err := AuditWorldDatapacks(worldAudit.Path)
			if err != nil {
				return err
			}
			if datapackAudit.Blocking() {
				recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
					datapackAudit.Describe(), worldAudit.Path)
				return fmt.Errorf("数据包目录校验失败，拒绝启动: %s", datapackAudit.Describe())
			}
			if len(datapackAudit.Findings) > 0 {
				a.writeLog("数据包告警: %s", datapackAudit.Describe())
			}
			playerAudit, err := AuditWorldPlayerData(worldAudit.Path)
			if err != nil {
				return err
			}
			if playerAudit.Blocking() {
				recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
					playerAudit.Describe(), worldAudit.Path)
				return fmt.Errorf("玩家数据目录校验失败，拒绝启动: %s", playerAudit.Describe())
			}
			if playerAudit.HasWarnings() {
				a.writeLog("玩家数据告警: %s", playerAudit.Describe())
			}
			regionAudit, regionErr := AuditWorldRegions(worldAudit.Path)
			if regionErr != nil {
				return regionErr
			}
			if regionAudit.Blocking() {
				recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
					regionAudit.Describe(), worldAudit.Path)
				return fmt.Errorf("世界区域文件校验失败，拒绝启动: %s", regionAudit.Describe())
			}
			if regionAudit.HasWarnings() {
				a.writeLog("世界区域文件告警: %s", regionAudit.Describe())
			}
		}
	}

	settingsAudit, settingsErr := AuditServerSettingsFile(cfg.ServerDir)
	if settingsErr != nil {
		return settingsErr
	}
	if settingsAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			settingsAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器配置校验失败，拒绝启动: %s", settingsAudit.Describe())
	}
	if settingsAudit.HasWarnings() {
		a.writeLog("服务器配置告警: %s", settingsAudit.Describe())
	}

	bindingAudit, bindingErr := AuditServerBinding(cfg.ServerDir)
	if bindingErr != nil {
		return bindingErr
	}
	if bindingAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			bindingAudit.Describe(), bindingAudit.Path)
		return fmt.Errorf("服务器网络暴露策略校验失败，拒绝启动: %s", bindingAudit.Describe())
	}
	if bindingAudit.HasWarnings() {
		a.writeLog("服务器网络暴露告警: %s", bindingAudit.Describe())
	}

	packAudit, packErr := AuditServerResourcePack(cfg.ServerDir)
	if packErr != nil {
		return packErr
	}
	if packAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			packAudit.Describe(), packAudit.Path)
		return fmt.Errorf("服务器资源包策略校验失败，拒绝启动: %s", packAudit.Describe())
	}
	if packAudit.HasWarnings() {
		a.writeLog("服务器资源包告警: %s", packAudit.Describe())
	}

	logAudit, logErr := AuditServerLogs(cfg.ServerDir)
	if logErr != nil {
		return logErr
	}
	if logAudit.Blocking() {
		recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
			logAudit.Describe(), logAudit.Dir)
		return fmt.Errorf("服务器日志目录校验失败，拒绝启动: %s", logAudit.Describe())
	}
	if logAudit.HasWarnings() {
		a.writeLog("服务器日志告警: %s", logAudit.Describe())
	}

	rconAudit, rconErr := AuditServerRcon(cfg.ServerDir)
	if rconErr != nil {
		return rconErr
	}
	if rconAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			rconAudit.Describe(), rconAudit.Path)
		return fmt.Errorf("服务器 RCON/Query 暴露面校验失败，拒绝启动: %s", rconAudit.Describe())
	}
	if rconAudit.HasWarnings() {
		a.writeLog("服务器 RCON/Query 告警: %s", rconAudit.Describe())
	}

	startupAudit := AuditServerStartupScripts(cfg.ServerDir)
	if startupAudit.Blocking() {
		recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
			startupAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器启动脚本校验失败，拒绝启动: %s", startupAudit.Describe())
	}
	if startupAudit.HasWarnings() {
		a.writeLog("服务器启动脚本告警: %s", startupAudit.Describe())
	}

	proxyAudit := AuditServerProxyTrust(cfg.ServerDir)
	if proxyAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			proxyAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器代理信任配置校验失败，拒绝启动: %s", proxyAudit.Describe())
	}
	if proxyAudit.HasWarnings() {
		a.writeLog("服务器代理信任告警: %s", proxyAudit.Describe())
	}

	fsPermAudit := AuditServerFSPermissions(cfg.ServerDir)
	if fsPermAudit.Blocking() {
		recordSecurityEvent(auditCategoryPermission, auditSeverityCritical, auditActionBlocked,
			fsPermAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器目录权限校验失败，拒绝启动: %s", fsPermAudit.Describe())
	}
	if fsPermAudit.HasWarnings() {
		a.writeLog("服务器目录权限告警: %s", fsPermAudit.Describe())
	}

	strayAudit := AuditServerStraySecrets(cfg.ServerDir)
	if strayAudit.Blocking() {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			strayAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器目录凭据校验失败，拒绝启动: %s", strayAudit.Describe())
	}
	if strayAudit.HasWarnings() {
		a.writeLog("服务器目录凭据告警: %s", strayAudit.Describe())
	}

	whitelistAudit := AuditServerWhitelist(cfg.ServerDir)
	if whitelistAudit.Blocking() {
		recordSecurityEvent(auditCategoryPermission, auditSeverityCritical, auditActionBlocked,
			whitelistAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器白名单校验失败，拒绝启动: %s", whitelistAudit.Describe())
	}
	if whitelistAudit.HasWarnings() {
		a.writeLog("服务器白名单告警: %s", whitelistAudit.Describe())
	}

	banAudit := AuditServerBanList(cfg.ServerDir)
	if banAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			banAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器封禁名单校验失败，拒绝启动: %s", banAudit.Describe())
	}
	if banAudit.HasWarnings() {
		a.writeLog("服务器封禁名单告警: %s", banAudit.Describe())
	}

	iconAudit := AuditServerIcon(cfg.ServerDir)
	if iconAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			iconAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器图标校验失败，拒绝启动: %s", iconAudit.Describe())
	}
	if iconAudit.HasWarnings() {
		a.writeLog("服务器图标告警: %s", iconAudit.Describe())
	}

	dataPackAudit := AuditServerDataPacks(cfg.ServerDir)
	if dataPackAudit.Blocking() {
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
			dataPackAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器数据包校验失败，拒绝启动: %s", dataPackAudit.Describe())
	}
	if dataPackAudit.HasWarnings() {
		a.writeLog("服务器数据包告警: %s", dataPackAudit.Describe())
	}

	accessControlAudit := AuditServerAccessControl(cfg.ServerDir)
	if accessControlAudit.Blocking() {
		recordSecurityEvent(auditCategoryPermission, auditSeverityCritical, auditActionBlocked,
			accessControlAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器访问控制校验失败，拒绝启动: %s", accessControlAudit.Describe())
	}
	if accessControlAudit.HasWarnings() {
		a.writeLog("服务器访问控制告警: %s", accessControlAudit.Describe())
	}

	pluginJarAudit := AuditServerPluginJars(cfg.ServerDir)
	if pluginJarAudit.Blocking() {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityCritical, auditActionBlocked,
			pluginJarAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器插件 jar 校验失败，拒绝启动: %s", pluginJarAudit.Describe())
	}
	if pluginJarAudit.HasWarnings() {
		a.writeLog("服务器插件 jar 告警: %s", pluginJarAudit.Describe())
	}

	crashReportAudit := AuditCrashReports(cfg.ServerDir)
	if crashReportAudit.Blocking() {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			crashReportAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器崩溃报告校验失败，拒绝启动: %s", crashReportAudit.Describe())
	}
	if crashReportAudit.HasWarnings() {
		a.writeLog("服务器崩溃报告告警: %s", crashReportAudit.Describe())
	}

	tlsAudit := AuditServerTLS(cfg.ServerDir)
	if tlsAudit.Blocking() {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			tlsAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器 TLS 校验失败，拒绝启动: %s", tlsAudit.Describe())
	}
	if tlsAudit.HasWarnings() {
		a.writeLog("服务器 TLS 告警: %s", tlsAudit.Describe())
	}

	worldRegionAudit := AuditServerWorldRegions(cfg.ServerDir)
	if worldRegionAudit.Blocking() {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			worldRegionAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器世界存档校验失败，拒绝启动: %s", worldRegionAudit.Describe())
	}
	if worldRegionAudit.HasWarnings() {
		a.writeLog("服务器世界存档告警: %s", worldRegionAudit.Describe())
	}

	portBindingAudit := AuditServerPorts(cfg.ServerDir)
	if portBindingAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			portBindingAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器端口绑定校验失败，拒绝启动: %s", portBindingAudit.Describe())
	}
	if portBindingAudit.HasWarnings() {
		a.writeLog("服务器端口绑定告警: %s", portBindingAudit.Describe())
	}

	logConfigAudit := AuditServerLogConfig(cfg.ServerDir)
	if logConfigAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			logConfigAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器日志配置校验失败，拒绝启动: %s", logConfigAudit.Describe())
	}
	if logConfigAudit.HasWarnings() {
		a.writeLog("服务器日志配置告警: %s", logConfigAudit.Describe())
	}

	tickConfigAudit := AuditServerTickConfig(cfg.ServerDir)
	if tickConfigAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			tickConfigAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器 tick 参数校验失败，拒绝启动: %s", tickConfigAudit.Describe())
	}
	if tickConfigAudit.HasWarnings() {
		a.writeLog("服务器 tick 参数告警: %s", tickConfigAudit.Describe())
	}

	jvmAgentAudit := AuditServerJVMAgents(cfg.ServerDir)
	if jvmAgentAudit.Blocking() {
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityCritical, auditActionBlocked,
			jvmAgentAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器 JVM agent 校验失败，拒绝启动: %s", jvmAgentAudit.Describe())
	}
	if jvmAgentAudit.HasWarnings() {
		a.writeLog("服务器 JVM agent 告警: %s", jvmAgentAudit.Describe())
	}

	budgetAudit := AuditServerBudget(cfg.ServerDir)
	if budgetAudit.Blocking() {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			budgetAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器磁盘占用校验失败，拒绝启动: %s", budgetAudit.Describe())
	}
	if budgetAudit.HasWarnings() {
		a.writeLog("服务器磁盘占用告警: %s", budgetAudit.Describe())
	}

	playerPrivacyAudit := AuditServerPlayerPrivacy(cfg.ServerDir)
	if playerPrivacyAudit.Blocking() {
		a.writeLog("security", "玩家身份数据审计阻断启动: "+playerPrivacyAudit.Describe())
		return fmt.Errorf("玩家身份数据未通过安全校验: %s", playerPrivacyAudit.Describe())
	}
	forkConfigAudit := AuditServerForkConfig(cfg.ServerDir)
	if forkConfigAudit.Blocking() {
		a.writeLog("security", "分支配置审计阻断启动: "+forkConfigAudit.Describe())
		return fmt.Errorf("分支配置未通过安全校验: %s", forkConfigAudit.Describe())
	}
	yamlHazardAudit := AuditServerYamlHazards(cfg.ServerDir)
	if yamlHazardAudit.Blocking() {
		a.writeLog("security", "YAML 构造审计阻断启动: "+yamlHazardAudit.Describe())
		return fmt.Errorf("YAML 配置未通过安全校验: %s", yamlHazardAudit.Describe())
	}
	permissionConfigAudit := AuditServerPermissionConfig(cfg.ServerDir)
	if permissionConfigAudit.Blocking() {
		a.writeLog("security", "权限配置审计阻断启动: "+permissionConfigAudit.Describe())
		return fmt.Errorf("权限配置未通过安全校验: %s", permissionConfigAudit.Describe())
	}
	startupSecretAudit := AuditServerStartupSecrets(cfg.ServerDir)
	if startupSecretAudit.Blocking() {
		a.writeLog("security", "启动脚本凭据审计阻断启动: "+startupSecretAudit.Describe())
		return fmt.Errorf("启动脚本凭据未通过安全校验: %s", startupSecretAudit.Describe())
	}
	commandAliasAudit := AuditServerCommandAliases(cfg.ServerDir)
	if commandAliasAudit.Blocking() {
		a.writeLog("security", "命令别名审计阻断启动: "+commandAliasAudit.Describe())
		return fmt.Errorf("命令别名未通过安全校验: %s", commandAliasAudit.Describe())
	}
	helpOverrideAudit := AuditServerHelpOverride(cfg.ServerDir)
	if helpOverrideAudit.Blocking() {
		a.writeLog("security", "帮助覆盖审计阻断启动: "+helpOverrideAudit.Describe())
		return fmt.Errorf("帮助覆盖未通过安全校验: %s", helpOverrideAudit.Describe())
	}
	statsAudit := AuditServerStats(cfg.ServerDir)
	if statsAudit.Blocking() {
		a.writeLog("security", "玩家统计审计阻断启动: "+statsAudit.Describe())
		return fmt.Errorf("玩家统计未通过安全校验: %s", statsAudit.Describe())
	}
	advancementAudit := AuditServerAdvancements(cfg.ServerDir)
	if advancementAudit.Blocking() {
		a.writeLog("security", "进度数据审计阻断启动: "+advancementAudit.Describe())
		return fmt.Errorf("进度数据未通过安全校验: %s", advancementAudit.Describe())
	}
	dataPackFilterAudit := AuditServerDataPackFilters(cfg.ServerDir)
	if dataPackFilterAudit.Blocking() {
		a.writeLog("security", "数据包过滤审计阻断启动: "+dataPackFilterAudit.Describe())
		return fmt.Errorf("数据包过滤未通过安全校验: %s", dataPackFilterAudit.Describe())
	}
	log4jAudit := AuditServerLog4jShell(cfg.ServerDir)
	if log4jAudit.Blocking() {
		a.writeLog("security", "log4j 组件审计阻断启动: "+log4jAudit.Describe())
		return fmt.Errorf("log4j 组件未通过安全校验: %s", log4jAudit.Describe())
	}
	proxyForwardAudit := AuditServerProxyForwarding(cfg.ServerDir)
	if proxyForwardAudit.Blocking() {
		a.writeLog("security", "代理转发审计阻断启动: "+proxyForwardAudit.Describe())
		return fmt.Errorf("代理转发配置未通过安全校验: %s", proxyForwardAudit.Describe())
	}
	connectionFloodAudit := AuditServerConnectionFlood(cfg.ServerDir)
	if connectionFloodAudit.Blocking() {
		a.writeLog("security", "连接洪泛审计阻断启动: "+connectionFloodAudit.Describe())
		return fmt.Errorf("连接节流配置未通过安全校验: %s", connectionFloodAudit.Describe())
	}
	packetLimiterAudit := AuditServerPacketLimiter(cfg.ServerDir)
	if packetLimiterAudit.Blocking() {
		a.writeLog("security", "数据包限速审计阻断启动: "+packetLimiterAudit.Describe())
		return fmt.Errorf("数据包限速配置未通过安全校验: %s", packetLimiterAudit.Describe())
	}
	propertiesBudgetAudit := AuditServerPropertiesBudget(cfg.ServerDir)
	if propertiesBudgetAudit.Blocking() {
		a.writeLog("security", "服务端属性预算审计阻断启动: "+propertiesBudgetAudit.Describe())
		return fmt.Errorf("服务端属性未通过安全校验: %s", propertiesBudgetAudit.Describe())
	}
	modJarAudit := AuditModJarManifests(cfg.ServerDir)
	if modJarAudit.Blocking() {
		a.writeLog("security", "模组清单审计阻断启动: "+modJarAudit.Describe())
		return fmt.Errorf("模组清单未通过安全校验: %s", modJarAudit.Describe())
	}
	pluginJarEntryAudit := AuditPluginJarEntries(cfg.ServerDir)
	if pluginJarEntryAudit.Blocking() {
		a.writeLog("security", "插件归档审计阻断启动: "+pluginJarEntryAudit.Describe())
		return fmt.Errorf("插件归档未通过安全校验: %s", pluginJarEntryAudit.Describe())
	}
	commandBlockAudit := AuditServerCommandBlocks(cfg.ServerDir)
	if commandBlockAudit.Blocking() {
		a.writeLog("security", "命令方块审计阻断启动: "+commandBlockAudit.Describe())
		return fmt.Errorf("命令方块配置未通过安全校验: %s", commandBlockAudit.Describe())
	}
	pluginUpdateAudit := AuditServerPluginUpdates(cfg.ServerDir)
	if pluginUpdateAudit.Blocking() {
		a.writeLog("security", "插件更新审计阻断启动: "+pluginUpdateAudit.Describe())
		return fmt.Errorf("插件更新配置未通过安全校验: %s", pluginUpdateAudit.Describe())
	}
	pluginMetricsAudit := AuditServerPluginMetrics(cfg.ServerDir)
	if pluginMetricsAudit.Blocking() {
		a.writeLog("security", "插件遥测审计阻断启动: "+pluginMetricsAudit.Describe())
		return fmt.Errorf("插件遥测配置未通过安全校验: %s", pluginMetricsAudit.Describe())
	}
	queryBindingAudit := AuditServerQueryBinding(cfg.ServerDir)
	if queryBindingAudit.Blocking() {
		a.writeLog("security", "查询绑定审计阻断启动: "+queryBindingAudit.Describe())
		return fmt.Errorf("查询绑定配置未通过安全校验: %s", queryBindingAudit.Describe())
	}
	entityCrammingAudit := AuditServerEntityCramming(cfg.ServerDir)
	if entityCrammingAudit.Blocking() {
		a.writeLog("security", "实体堆积审计阻断启动: "+entityCrammingAudit.Describe())
		return fmt.Errorf("实体堆积配置未通过安全校验: %s", entityCrammingAudit.Describe())
	}
	movementGuardAudit := AuditServerMovementGuards(cfg.ServerDir)
	if movementGuardAudit.Blocking() {
		a.writeLog("security", "移动容量审计阻断启动: "+movementGuardAudit.Describe())
		return fmt.Errorf("移动容量配置未通过安全校验: %s", movementGuardAudit.Describe())
	}
	proxyAuthAudit := AuditServerProxyAuth(cfg.ServerDir)
	if proxyAuthAudit.Blocking() {
		a.writeLog("security", "代理鉴权审计阻断启动: "+proxyAuthAudit.Describe())
		return fmt.Errorf("服务器代理鉴权配置未通过安全校验: %s", proxyAuthAudit.Describe())
	}
	antiXrayAudit := AuditServerAntiXray(cfg.ServerDir)
	if antiXrayAudit.Blocking() {
		a.writeLog("security", "反矿透审计阻断启动: "+antiXrayAudit.Describe())
		return fmt.Errorf("服务器反矿透配置未通过安全校验: %s", antiXrayAudit.Describe())
	}
	watchdogAudit := AuditServerWatchdog(cfg.ServerDir)
	if watchdogAudit.Blocking() {
		a.writeLog("security", "看门狗审计阻断启动: "+watchdogAudit.Describe())
		return fmt.Errorf("服务器看门狗与重启配置未通过安全校验: %s", watchdogAudit.Describe())
	}
	pregenAudit := AuditServerPregen(cfg.ServerDir)
	if pregenAudit.Blocking() {
		a.writeLog("security", "区块预生成审计阻断启动: "+pregenAudit.Describe())
		return fmt.Errorf("服务器区块预生成配置未通过安全校验: %s", pregenAudit.Describe())
	}
	dynmapAudit := AuditServerDynmap(cfg.ServerDir)
	if dynmapAudit.Blocking() {
		a.writeLog("security", "网页地图审计阻断启动: "+dynmapAudit.Describe())
		return fmt.Errorf("服务器网页地图配置未通过安全校验: %s", dynmapAudit.Describe())
	}
	unsafeToggleAudit := AuditServerUnsafeToggles(cfg.ServerDir)
	if unsafeToggleAudit.Blocking() {
		a.writeLog("security", "实验开关审计阻断启动: "+unsafeToggleAudit.Describe())
		return fmt.Errorf("服务器实验性开关未通过安全校验: %s", unsafeToggleAudit.Describe())
	}
	blueMapAudit := AuditServerBlueMap(cfg.ServerDir)
	if blueMapAudit.Blocking() {
		a.writeLog("security", "网页地图审计阻断启动: "+blueMapAudit.Describe())
		return fmt.Errorf("网页地图审计未通过安全校验: %s", blueMapAudit.Describe())
	}
	userCacheAudit := AuditServerUserCache(cfg.ServerDir)
	if userCacheAudit.Blocking() {
		a.writeLog("security", "玩家缓存审计阻断启动: "+userCacheAudit.Describe())
		return fmt.Errorf("玩家缓存审计未通过安全校验: %s", userCacheAudit.Describe())
	}
	bannedIPsAudit := AuditServerBannedIPs(cfg.ServerDir)
	if bannedIPsAudit.Blocking() {
		a.writeLog("security", "IP 封禁清单审计阻断启动: "+bannedIPsAudit.Describe())
		return fmt.Errorf("IP 封禁清单审计未通过安全校验: %s", bannedIPsAudit.Describe())
	}
	bukkitConfigAudit := AuditServerBukkitConfig(cfg.ServerDir)
	if bukkitConfigAudit.Blocking() {
		a.writeLog("security", "Bukkit 配置审计阻断启动: "+bukkitConfigAudit.Describe())
		return fmt.Errorf("Bukkit 配置审计未通过安全校验: %s", bukkitConfigAudit.Describe())
	}
	worldNameAudit := AuditServerWorldName(cfg.ServerDir)
	if worldNameAudit.Blocking() {
		a.writeLog("security", "世界目录审计阻断启动: "+worldNameAudit.Describe())
		return fmt.Errorf("世界目录审计未通过安全校验: %s", worldNameAudit.Describe())
	}
	worldSeedAudit := AuditServerWorldSeed(cfg.ServerDir)
	if worldSeedAudit.Blocking() {
		a.writeLog("security", "世界种子审计阻断启动: "+worldSeedAudit.Describe())
		return fmt.Errorf("世界种子审计未通过安全校验: %s", worldSeedAudit.Describe())
	}
	opsJsonAudit := AuditServerOpsJson(cfg.ServerDir)
	if opsJsonAudit.Blocking() {
		a.writeLog("security", "操作员清单审计阻断启动: "+opsJsonAudit.Describe())
		return fmt.Errorf("服务器操作员清单未通过安全校验: %s", opsJsonAudit.Describe())
	}
	whitelistFileAudit := AuditServerWhitelistFile(cfg.ServerDir)
	if whitelistFileAudit.Blocking() {
		a.writeLog("security", "白名单文件审计阻断启动: "+whitelistFileAudit.Describe())
		return fmt.Errorf("服务器白名单文件未通过安全校验: %s", whitelistFileAudit.Describe())
	}
	commandsYmlAudit := AuditServerCommandsYml(cfg.ServerDir)
	if commandsYmlAudit.Blocking() {
		a.writeLog("security", "命令别名审计阻断启动: "+commandsYmlAudit.Describe())
		return fmt.Errorf("服务器命令别名配置未通过安全校验: %s", commandsYmlAudit.Describe())
	}
	helpYmlAudit := AuditServerHelpYml(cfg.ServerDir)
	if helpYmlAudit.Blocking() {
		a.writeLog("security", "帮助配置审计阻断启动: "+helpYmlAudit.Describe())
		return fmt.Errorf("服务器帮助配置未通过安全校验: %s", helpYmlAudit.Describe())
	}
	spigotAudit := AuditServerSpigotConfig(cfg.ServerDir)
	if spigotAudit.Blocking() {
		a.writeLog("security", "Spigot 配置审计阻断启动: "+spigotAudit.Describe())
		return fmt.Errorf("服务器 Spigot 配置未通过安全校验: %s", spigotAudit.Describe())
	}
	paperAudit := AuditServerPaperConfig(cfg.ServerDir)
	if paperAudit.Blocking() {
		a.writeLog("security", "Paper 全局配置审计阻断启动: "+paperAudit.Describe())
		return fmt.Errorf("服务器 Paper 全局配置未通过安全校验: %s", paperAudit.Describe())
	}
	eulaAudit := AuditServerEula(cfg.ServerDir)
	if eulaAudit.Blocking() {
		a.writeLog("security", "EULA 协议审计阻断启动: "+eulaAudit.Describe())
		return fmt.Errorf("服务器 EULA 协议未通过安全校验: %s", eulaAudit.Describe())
	}
	iconFileAudit := AuditServerIconFile(cfg.ServerDir)
	if iconFileAudit.Blocking() {
		a.writeLog("security", "服务器图标审计阻断启动: "+iconFileAudit.Describe())
		return fmt.Errorf("服务器图标未通过安全校验: %s", iconFileAudit.Describe())
	}
	permissionsFileAudit := AuditServerPermissions(cfg.ServerDir)
	if permissionsFileAudit.Blocking() {
		a.writeLog("security", "权限配置审计阻断启动: "+permissionsFileAudit.Describe())
		return fmt.Errorf("服务器权限配置未通过安全校验: %s", permissionsFileAudit.Describe())
	}
	bannedPlayersFileAudit := AuditServerBannedPlayers(cfg.ServerDir)
	if bannedPlayersFileAudit.Blocking() {
		a.writeLog("security", "封禁名单审计阻断启动: "+bannedPlayersFileAudit.Describe())
		return fmt.Errorf("服务器封禁名单未通过安全校验: %s", bannedPlayersFileAudit.Describe())
	}
	paperWorldAudit := AuditServerPaperWorldDefaults(cfg.ServerDir)
	if paperWorldAudit.Blocking() {
		a.writeLog("security", "Paper 世界默认配置审计阻断启动: "+paperWorldAudit.Describe())
		return fmt.Errorf("服务器 Paper 世界默认配置未通过安全校验: %s", paperWorldAudit.Describe())
	}
	purpurConfigAudit := AuditServerPurpurConfig(cfg.ServerDir)
	if purpurConfigAudit.Blocking() {
		a.writeLog("security", "Purpur 配置审计阻断启动: "+purpurConfigAudit.Describe())
		return fmt.Errorf("服务器 Purpur 配置未通过安全校验: %s", purpurConfigAudit.Describe())
	}
	levelDataAudit := AuditServerLevelData(cfg.ServerDir)
	if levelDataAudit.Blocking() {
		a.writeLog("security", "存档元数据审计阻断启动: "+levelDataAudit.Describe())
		return fmt.Errorf("服务器存档元数据未通过安全校验: %s", levelDataAudit.Describe())
	}
	propertiesEncodingAudit := AuditServerPropertiesEncoding(cfg.ServerDir)
	if propertiesEncodingAudit.Blocking() {
		a.writeLog("security", "属性文件编码审计阻断启动: "+propertiesEncodingAudit.Describe())
		return fmt.Errorf("服务器属性文件编码未通过安全校验: %s", propertiesEncodingAudit.Describe())
	}
	jvmArgsFileAudit := AuditServerJvmArgsFile(cfg.ServerDir)
	if jvmArgsFileAudit.Blocking() {
		a.writeLog("security", "JVM 参数审计阻断启动: "+jvmArgsFileAudit.Describe())
		return fmt.Errorf("服务器 JVM 参数未通过安全校验: %s", jvmArgsFileAudit.Describe())
	}
	crashReportsAudit := AuditServerCrashReports(cfg.ServerDir)
	if crashReportsAudit.Blocking() {
		a.writeLog("security", "崩溃报告审计阻断启动: "+crashReportsAudit.Describe())
		return fmt.Errorf("服务器崩溃报告未通过安全校验: %s", crashReportsAudit.Describe())
	}
	configConsistencyAudit := AuditServerConfigConsistency(cfg.ServerDir)
	if configConsistencyAudit.Blocking() {
		a.writeLog("security", "配置一致性审计阻断启动: "+configConsistencyAudit.Describe())
		return fmt.Errorf("服务器配置组合未通过安全校验: %s", configConsistencyAudit.Describe())
	}
	onlineModeAudit := AuditServerOnlineMode(cfg.ServerDir)
	if onlineModeAudit.Blocking() {
		a.writeLog("security", "在线认证审计阻断启动: "+onlineModeAudit.Describe())
		return fmt.Errorf("server.properties 在线认证配置未通过安全校验: %s", onlineModeAudit.Describe())
	}
	whitelistCoverageAudit := AuditServerWhitelistCoverage(cfg.ServerDir)
	if whitelistCoverageAudit.Blocking() {
		a.writeLog("security", "白名单覆盖审计阻断启动: "+whitelistCoverageAudit.Describe())
		return fmt.Errorf("白名单覆盖配置未通过安全校验: %s", whitelistCoverageAudit.Describe())
	}
	hardcoreAudit := AuditServerHardcore(cfg.ServerDir)
	if hardcoreAudit.Blocking() {
		a.writeLog("security", "难度模式审计阻断启动: "+hardcoreAudit.Describe())
		return fmt.Errorf("难度与游戏模式配置未通过安全校验: %s", hardcoreAudit.Describe())
	}
	maxPlayersAudit := AuditServerMaxPlayers(cfg.ServerDir)
	if maxPlayersAudit.Blocking() {
		a.writeLog("security", "容量限流审计阻断启动: "+maxPlayersAudit.Describe())
		return fmt.Errorf("容量与限流配置未通过安全校验: %s", maxPlayersAudit.Describe())
	}
	banEnforcementAudit := AuditServerBanEnforcement(cfg.ServerDir)
	if banEnforcementAudit.Blocking() {
		a.writeLog("security", "封禁名单审计阻断启动: "+banEnforcementAudit.Describe())
		return fmt.Errorf("封禁与管理员名单未通过安全校验: %s", banEnforcementAudit.Describe())
	}
	exploitTogglesAudit := AuditServerExploitToggles(cfg.ServerDir)
	if exploitTogglesAudit.Blocking() {
		a.writeLog("security", "作弊开关审计阻断启动: "+exploitTogglesAudit.Describe())
		return fmt.Errorf("作弊与权限开关配置未通过安全校验: %s", exploitTogglesAudit.Describe())
	}
	pluginConfigAudit := AuditServerPluginConfig(cfg.ServerDir)
	if pluginConfigAudit.Blocking() {
		recordSecurityEvent(auditCategoryPermission, auditSeverityCritical, auditActionBlocked,
			pluginConfigAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器插件配置校验失败，拒绝启动: %s", pluginConfigAudit.Describe())
	}
	if pluginConfigAudit.HasWarnings() {
		a.writeLog("服务器插件配置告警: %s", pluginConfigAudit.Describe())
	}

	backupAudit := AuditServerBackups(cfg.ServerDir)
	if backupAudit.Blocking() {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			backupAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器备份校验失败，拒绝启动: %s", backupAudit.Describe())
	}
	if backupAudit.HasWarnings() {
		a.writeLog("服务器备份告警: %s", backupAudit.Describe())
	}

	libraryAudit := AuditServerLibraries(cfg.ServerDir)
	if libraryAudit.Blocking() {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityCritical, auditActionBlocked,
			libraryAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器依赖库校验失败，拒绝启动: %s", libraryAudit.Describe())
	}
	if libraryAudit.HasWarnings() {
		a.writeLog("服务器依赖库告警: %s", libraryAudit.Describe())
	}

	sessionLockAudit := AuditServerSessionLocks(cfg.ServerDir)
	if sessionLockAudit.Blocking() {
		recordSecurityEvent(auditCategoryReclaim, auditSeverityCritical, auditActionBlocked,
			sessionLockAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器世界占用校验失败，拒绝启动: %s", sessionLockAudit.Describe())
	}
	if sessionLockAudit.HasWarnings() {
		a.writeLog("服务器世界占用告警: %s", sessionLockAudit.Describe())
	}

	jmxAudit := AuditServerJMX(cfg.ServerDir)
	if jmxAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			jmxAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器 JMX 暴露面校验失败，拒绝启动: %s", jmxAudit.Describe())
	}
	if jmxAudit.HasWarnings() {
		a.writeLog("服务器 JMX 暴露面告警: %s", jmxAudit.Describe())
	}

	jarCpAudit := AuditServerJarClassPath(cfg.ServerDir)
	if jarCpAudit.Blocking() {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityCritical, auditActionBlocked,
			jarCpAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器 jar Class-Path 校验失败，拒绝启动: %s", jarCpAudit.Describe())
	}
	if jarCpAudit.HasWarnings() {
		a.writeLog("服务器 jar Class-Path 告警: %s", jarCpAudit.Describe())
	}

	envAudit := AuditServerEnvironmentHijack(cfg.ServerDir)
	if envAudit.Blocking() {
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityCritical, auditActionBlocked,
			envAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器环境变量校验失败，拒绝启动: %s", envAudit.Describe())
	}
	if envAudit.HasWarnings() {
		a.writeLog("服务器环境变量告警: %s", envAudit.Describe())
	}

	pluginPermAudit := AuditServerPluginPermissions(cfg.ServerDir)
	if pluginPermAudit.Blocking() {
		recordSecurityEvent(auditCategoryPermission, auditSeverityCritical, auditActionBlocked,
			pluginPermAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器插件权限校验失败，拒绝启动: %s", pluginPermAudit.Describe())
	}
	if pluginPermAudit.HasWarnings() {
		a.writeLog("服务器插件权限告警: %s", pluginPermAudit.Describe())
	}

	accessAudit, accessErr := AuditServerAccess(cfg.ServerDir)
	if accessErr != nil {
		return accessErr
	}
	if accessAudit.Blocking() {
		recordSecurityEvent(auditCategoryPermission, auditSeverityCritical, auditActionBlocked,
			accessAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器权限文件校验失败，拒绝启动: %s", accessAudit.Describe())
	}
	if accessAudit.HasWarnings() {
		a.writeLog("服务器权限告警: %s", accessAudit.Describe())
	}

	operatorAudit, operatorErr := AuditServerOperators(cfg.ServerDir)
	if operatorErr != nil {
		return operatorErr
	}
	if operatorAudit.Blocking() {
		recordSecurityEvent(auditCategoryPermission, auditSeverityCritical, auditActionBlocked,
			operatorAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器权限名单校验失败，拒绝启动: %s", operatorAudit.Describe())
	}
	if operatorAudit.HasWarnings() {
		a.writeLog("服务器权限名单告警: %s", operatorAudit.Describe())
	}

	playerCacheAudit, playerCacheErr := AuditPlayerCache(cfg.ServerDir)
	if playerCacheErr != nil {
		return playerCacheErr
	}
	if playerCacheAudit.Blocking() {
		recordSecurityEvent(auditCategoryPermission, auditSeverityCritical, auditActionBlocked,
			playerCacheAudit.Describe(), playerCacheAudit.Path)
		return fmt.Errorf("玩家缓存校验失败，拒绝启动: %s", playerCacheAudit.Describe())
	}
	if playerCacheAudit.HasWarnings() {
		a.writeLog("玩家缓存告警: %s", playerCacheAudit.Describe())
	}

	pluginAudit, pluginErr := AuditServerPlugins(cfg.ServerDir)
	if pluginErr != nil {
		return pluginErr
	}
	if pluginAudit.Blocking() {
		recordSecurityEvent(auditCategoryPermission, auditSeverityCritical, auditActionBlocked,
			pluginAudit.Describe(), pluginAudit.Dir)
		return fmt.Errorf("插件目录校验失败，拒绝启动: %s", pluginAudit.Describe())
	}
	if pluginAudit.HasWarnings() {
		a.writeLog("插件告警: %s", pluginAudit.Describe())
	}

	modManifestAudit, modManifestErr := AuditServerModManifest(filepath.Join(cfg.ServerDir, "mods"))
	if modManifestErr != nil {
		return modManifestErr
	}
	if modManifestAudit.Blocking() {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityCritical, auditActionBlocked,
			modManifestAudit.Describe(), modManifestAudit.Dir)
		return fmt.Errorf("模组清单校验失败，拒绝启动: %s", modManifestAudit.Describe())
	}
	if modManifestAudit.HasWarnings() {
		a.writeLog("模组清单告警: %s", modManifestAudit.Describe())
	}

	remoteAudit, remoteErr := AuditServerRemoteAdmin(cfg.ServerDir)
	if remoteErr != nil {
		return remoteErr
	}
	if remoteAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			remoteAudit.Describe(), remoteAudit.Path)
		return fmt.Errorf("服务器远程管理配置校验失败，拒绝启动: %s", remoteAudit.Describe())
	}
	if remoteAudit.HasWarnings() {
		a.writeLog("服务器远程管理告警: %s", remoteAudit.Describe())
	}

	portAudit, portErr := AuditServerPortExposure(cfg.ServerDir)
	if portErr != nil {
		return portErr
	}
	if portAudit.Blocking() {
		recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
			portAudit.Describe(), portAudit.Path)
		return fmt.Errorf("端口暴露校验失败，拒绝启动: %s", portAudit.Describe())
	}
	if portAudit.HasWarnings() {
		a.writeLog("端口暴露告警: %s", portAudit.Describe())
	}

	surfaceAudit, surfaceErr := AuditServerSurface(cfg.ServerDir)
	if surfaceErr != nil {
		return surfaceErr
	}
	if surfaceAudit.Blocking() {
		recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
			surfaceAudit.Describe(), cfg.ServerDir)
		return fmt.Errorf("服务器目录根层校验失败，拒绝启动: %s", surfaceAudit.Describe())
	}
	if surfaceAudit.HasWarnings() {
		a.writeLog("服务器目录根层告警: %s", surfaceAudit.Describe())
	}

	baselineAudit, baselineErr := AuditServerConfigBaseline(cfg.ServerDir, "")
	if baselineErr != nil {
		a.writeLog("服务器配置基线不可用: %v", baselineErr)
	} else if baselineAudit.HasWarnings() {
		a.writeLog("服务器配置基线变化: %s", baselineAudit.Describe())
	}

	javaEntry, err := a.SelectJavaForVersion(cfg.Version)
	if err != nil {
		return fmt.Errorf("选择 Java 失败: %v", err)
	}
	javaPath := javaEntry.Path
	// AuditServerLaunch 只收敛了工作目录/版本名拼出的 jar/内存，java 可执行路径由
	// SelectJavaForVersion 决定，这里在真正 exec 前再做一次绝对/UNC/穿越/扩展名校验，
	// 防止被改写的 JDK 记录或解析结果把服务器 JVM 指到网络共享或穿越路径。
	if javaFindings := auditJavaExe(javaPath); len(javaFindings) > 0 {
		return fmt.Errorf("服务器 java 可执行审计未通过，拒绝启动: %s", javaFindings[0].Code)
	}

	jarName := cfg.Version + "-server.jar"
	jarPath := filepath.Join(cfg.ServerDir, jarName)
	jarAudit, jarAuditErr := AuditServerJar(jarPath, func(path string) (bool, bool) {
		meta, ok := loadCachedFileMeta(path)
		if !ok {
			return false, false
		}
		return a.verifyCachedFile(path, meta.SHA1), true
	})
	if jarAuditErr != nil {
		return fmt.Errorf("服务端 JAR 完整性检查失败: %v", jarAuditErr)
	}
	if jarAudit.Blocking() {
		recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
			describeServerJarAudit(jarAudit), jarPath)
		return fmt.Errorf("服务端 JAR 完整性校验失败，拒绝启动: %s", describeServerJarAudit(jarAudit))
	}
	if len(jarAudit.Warnings) > 0 {
		a.writeLog("服务端 JAR 校验告警: %s", describeServerJarAudit(jarAudit))
	}
	maxMem := fmt.Sprintf("%dM", cfg.MaxMemory)
	minMem := fmt.Sprintf("%dM", cfg.MinMemory)
	// 专用服务端会把玩家名 / 聊天经 log4j 记入控制台，旧版服务端 jar 同样受 Log4Shell
	// 影响（攻击者进服即可投递 JNDI 载荷）。这些 JVM 参数全由启动器生成，没有外部
	// JSON 覆盖问题，但仍统一走强制内核：补 log4j 消息 lookup 关闭与 JNDI 远程
	// codebase 禁用，再拼 -jar / nogui 程序参数。
	jvmArgs := applyEnforcedJvmProperties([]string{
		"-server",
		"-XX:+UseG1GC",
		fmt.Sprintf("-Xmx%s", maxMem),
		fmt.Sprintf("-Xms%s", minMem),
		"-XX:+UseCompressedOops",
	})
	args := append(jvmArgs, "-jar", jarName, "nogui")

	cmd := exec.Command(javaPath, args...)
	cmd.Dir = cfg.ServerDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// 内置服务端是长期运行的独立 JVM，同样必须剥离 JAVA_TOOL_OPTIONS
	// 一族隐式参数变量，避免服务端进程被环境注入 javaagent / 恶意类路径。
	a.applySanitizedJVMEnv(cmd, "DedicatedServer", nil)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("获取 stdin 失败: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("获取 stdout 失败: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("获取 stderr 失败: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动服务器失败: %v", err)
	}

	readyCh := make(chan struct{}, 1)
	serverMgr.cmd = cmd
	serverMgr.stdin = stdin
	serverMgr.logBuffer = make([]string, 0)
	serverMgr.ctx = a.ctx
	serverMgr.readyCh = readyCh
	serverMgr.status = ServerStatus{
		Running: true,
		Name:    name,
		Version: cfg.Version,
		Port:    cfg.Port,
		PID:     cmd.Process.Pid,
		Ready:   false,
	}
	// 新一轮服务端进程：清空上一会话遗留的控制台灌入冷却 / 窗口计数。
	serverConsoleGate.reset()

	go func() {
		scanner := make(chan string, 200)
		var wg sync.WaitGroup
		pipeOutput := func(r io.Reader) {
			defer wg.Done()
			s := bufio.NewScanner(r)
			// 服务端日志通常很短，但堆栈 / JSON 单行可能到几十 KB；
			// 缓冲区上限 1 MiB，超出的异常超长行直接结束扫描，避免无界增长。
			s.Buffer(make([]byte, 0, 64*1024), maxServerLogLineBytes)
			for s.Scan() {
				line := strings.TrimRight(s.Text(), "\r")
				if line != "" {
					scanner <- line
				}
			}
		}
		wg.Add(2)
		go pipeOutput(stdout)
		go pipeOutput(stderr)
		// 两个读取协程都退出（进程结束、管道关闭）后再关闭 channel，
		// 否则外层 range 永久阻塞，每次启动服务器都会泄漏一个协程。
		go func() {
			wg.Wait()
			close(scanner)
		}()
		for line := range scanner {
			serverMgr.mu.Lock()
			serverMgr.logBuffer = append(serverMgr.logBuffer, line)
			if len(serverMgr.logBuffer) > 500 {
				serverMgr.logBuffer = serverMgr.logBuffer[len(serverMgr.logBuffer)-500:]
			}
			if !serverMgr.status.Ready {
				if (strings.Contains(line, "Done (") && strings.Contains(line, ")! For help, type \"help\"")) ||
					(strings.Contains(line, "完成 (") && strings.Contains(line, ")! 如需帮助，请输入 \"help\"")) {
					serverMgr.status.Ready = true
					select {
					case readyCh <- struct{}{}:
					default:
					}
					runtime.EventsEmit(serverMgr.ctx, "serverReady")
					runtime.EventsEmit(serverMgr.ctx, "serverStatus", serverMgr.status)
				}
			}
			serverMgr.mu.Unlock()
			runtime.EventsEmit(a.ctx, "serverLog", sanitizeLogLine(line))
		}
	}()

	go func() {
		cmd.Wait()
		serverMgr.mu.Lock()
		serverMgr.status.Running = false
		serverMgr.status.Ready = false
		serverMgr.status.PID = 0
		serverMgr.mu.Unlock()
		runtime.EventsEmit(a.ctx, "serverStatus", serverMgr.status)
	}()

	return nil
}

// WaitForServerReady 等待服务器启动完毕
func (a *App) WaitForServerReady() error {
	serverMgr.mu.Lock()
	readyCh := serverMgr.readyCh
	if serverMgr.status.Ready {
		serverMgr.mu.Unlock()
		return nil
	}
	serverMgr.mu.Unlock()
	if readyCh == nil {
		return fmt.Errorf("服务器未在运行")
	}
	select {
	case <-readyCh:
		return nil
	case <-time.After(180 * time.Second):
		return fmt.Errorf("服务器启动超时（3分钟）")
	}
}

// StopServer 停止服务器
func (a *App) StopServer() error {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	if !serverMgr.status.Running || serverMgr.stdin == nil {
		return fmt.Errorf("服务器未在运行")
	}
	_, err := serverMgr.stdin.Write([]byte("stop\n"))
	if err != nil {
		if serverMgr.cmd != nil && serverMgr.cmd.Process != nil {
			serverMgr.cmd.Process.Kill()
		}
	}
	return nil
}

// SendServerCommand 向服务器发送命令
func (a *App) SendServerCommand(cmd string) error {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	if !serverMgr.status.Running || serverMgr.stdin == nil {
		return fmt.Errorf("服务器未在运行")
	}
	// 统一走控制台净化内核：拒绝夹带换行 / NUL / 其它控制字符 / 非法 UTF-8 的行，
	// 并限制单行长度，防止渲染层借 stdin 通道做命令注入或打爆服务端日志与存档。
	safeCmd, reason := SanitizeConsoleCommand(cmd)
	if reason != consoleRejectNone {
		recordSecurityEvent(auditCategoryConsole, auditSeverityWarn, auditActionRejected,
			"SendServerCommand", "拒绝非法控制台命令: "+reason)
		return fmt.Errorf("非法的服务器命令: %s", reason)
	}
	// 高速灌入限流：超窗即进入冷却，循环刷 say/fill 等会落盘的命令会被挡下。
	if !serverConsoleGate.allow(time.Now()) {
		recordSecurityEvent(auditCategoryConsole, auditSeverityWarn, auditActionRepeated,
			"SendServerCommand", "控制台命令触发灌入限流，进入冷却")
		return fmt.Errorf("命令发送过于频繁，请稍后再试")
	}
	_, err := serverMgr.stdin.Write([]byte(safeCmd + "\n"))
	return err
}

// GetServerStatus 获取服务器状态
func (a *App) GetServerStatus() ServerStatus {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	return serverMgr.status
}

// GetServerLogs 获取服务器日志
func (a *App) GetServerLogs() []string {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	result := make([]string, len(serverMgr.logBuffer))
	copy(result, serverMgr.logBuffer)
	return result
}

// getServerConfig 读取服务器配置
// 安全加固: 校验 name 不含路径遍历字符
// validateLoadedServerConfig 在信任磁盘上的 config.json 之前重新校验全部字段。
//
// 创建时的校验只挡得住前端正常流程；config.json 之后还可能被手工编辑、云盘同步、
// 旧版本写坏或被其他进程篡改。这里的字段（尤其 Version、ServerDir）随后会进入
// 文件路径拼接与 `java -jar <version>-server.jar`，属于代码执行面，因此加载时
// 必须像创建时一样逐项过白名单，任何越界 / 非法值都直接拒绝，绝不带病启动。
func (a *App) validateLoadedServerConfig(cfg *ServerConfig) error {
	if cfg == nil {
		return fmt.Errorf("空服务器配置")
	}
	if sanitizeServerName(cfg.Name) == "" {
		return fmt.Errorf("无效的服务器名称: %q", cfg.Name)
	}
	if err := sanitizePathComponent(cfg.Version); err != nil {
		return fmt.Errorf("无效的版本号: %v", err)
	}
	if !isValidPort(cfg.Port) {
		return fmt.Errorf("无效的端口号: %d", cfg.Port)
	}
	if !isValidMemory(cfg.MaxMemory) || !isValidMemory(cfg.MinMemory) {
		return fmt.Errorf("无效的内存配置")
	}
	if cfg.MinMemory > cfg.MaxMemory {
		return fmt.Errorf("最小内存不能大于最大内存")
	}
	serverRoot := filepath.Clean(a.GetServerDir())
	dir := filepath.Clean(cfg.ServerDir)
	if dir == "" || !filepath.IsAbs(dir) || isPathTraversal(serverRoot, dir) {
		return fmt.Errorf("服务器目录越界或非法: %q", cfg.ServerDir)
	}
	return nil
}

func (a *App) getServerConfig(name string) (*ServerConfig, error) {
	if err := sanitizePathComponent(name); err != nil {
		return nil, fmt.Errorf("无效的服务器名称")
	}
	serverDir := a.GetServerDir()
	configPath := filepath.Join(serverDir, name, "QGL", "config.json")
	var cfg ServerConfig
	if err := readPrivateStoreJSON(configPath, &cfg, "服务器配置"); err != nil {
		list, listErr := a.GetServerList()
		if listErr != nil {
			return nil, fmt.Errorf("读取配置失败: %v", listErr)
		}
		for i := range list {
			if list[i].Name == name {
				return &list[i], nil
			}
		}
		return nil, fmt.Errorf("找不到服务器 %s", name)
	}
	// 加载即校验：拒绝被篡改 / 写坏的配置进入后续 java -jar 执行路径。
	if err := a.validateLoadedServerConfig(&cfg); err != nil {
		return nil, fmt.Errorf("服务器配置不安全: %v", err)
	}
	return &cfg, nil
}

// SetServerOnlineMode 设置服务器正版验证
func (a *App) SetServerOnlineMode(name string, onlineMode bool) error {
	cfg, err := a.getServerConfig(name)
	if err != nil {
		return err
	}
	if isPathTraversal(a.GetServerDir(), cfg.ServerDir) {
		return fmt.Errorf("服务器目录路径不安全，拒绝修改")
	}
	propPath := filepath.Join(cfg.ServerDir, "server.properties")
	// 用保序、去重复键、校验布尔值的读写器替换原先的朴素行拆分，
	// 避免 CRLF 漏匹配 / 重复 online-mode 键冲突 / 非法值写入。
	if err := updateServerProperty(propPath, "online-mode", strconv.FormatBool(onlineMode), validateBoolProperty); err != nil {
		return err
	}
	cfg.OnlineMode = onlineMode
	qglDir := filepath.Join(cfg.ServerDir, "QGL")
	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	if err := secureWritePrivateFile(filepath.Join(qglDir, "config.json"), cfgData); err != nil {
		return fmt.Errorf("同步配置失败: %v", err)
	}
	return nil
}

// GenerateConnectionCode 生成连接码和直连地址
func (a *App) GenerateConnectionCode(serverName string) (map[string]string, error) {
	cfg, err := a.getServerConfig(serverName)
	if err != nil {
		return nil, err
	}
	ip, err := getLocalIP()
	if err != nil {
		return nil, fmt.Errorf("获取本机 IP 失败: %v", err)
	}
	// 生成侧也走严格 IPv4 归一：本机网卡返回的地址必须是合法四段 IPv4，
	// 否则宁可不生成连接码，也不把脏地址编进码里。
	normIP, ok := NormalizeIPv4(strings.TrimSpace(ip))
	if !ok {
		return nil, fmt.Errorf("IP 地址格式异常: %s", ip)
	}
	if !isValidPort(cfg.Port) {
		return nil, fmt.Errorf("服务器端口号无效: %d", cfg.Port)
	}
	// 编码统一交给连接码内核，保证“编得出就解得回”，不再在本方法内手拼。
	code, why := EncodeConnectionCode(normIP, cfg.Port)
	if why != connRejectNone {
		return nil, fmt.Errorf("生成连接码失败: %s", describeConnReject(why))
	}
	directAddr := fmt.Sprintf("%s:%d", normIP, cfg.Port)
	return map[string]string{
		"code":       code,
		"directAddr": directAddr,
	}, nil
}

// ParseConnectionCode 解析连接码。
// 安全加固: 解析逻辑全部收敛到 connectioncodeguard 纯函数内核——
// 首段（含 X<n>）严格 0-255 与位数限制，后三段十六进制 0-255，端口走统一
// isValidPort，末端再过 netaddrguard 形态校验。畸形连接码（X999 / X-1 / 超长
// 前缀 / 越界段或端口）一律拒绝并留审计，绝不返回半残地址。
func (a *App) ParseConnectionCode(code string) (string, error) {
	address, why := DecodeConnectionCode(strings.TrimSpace(code))
	if why != connRejectNone {
		recordSecurityEvent(auditCategoryConfig, auditSeverityWarn, auditActionRejected,
			"server", "拒绝畸形局域网连接码("+why+")")
		return "", fmt.Errorf("%s", describeConnReject(why))
	}
	return address, nil
}

// getLocalIP 获取本机局域网 IP
func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return getLocalIPByInterface(), nil
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// getLocalIPByInterface 备选方案：遍历网卡获取局域网 IP
func getLocalIPByInterface() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return "127.0.0.1"
}

// DeleteServer 删除服务器
func (a *App) DeleteServer(name string) error {
	cfg, err := a.getServerConfig(name)
	if err != nil {
		return err
	}
	serverMgr.mu.Lock()
	if serverMgr.status.Running && serverMgr.status.Name == name {
		serverMgr.mu.Unlock()
		a.StopServer()
		time.Sleep(1 * time.Second)
	} else {
		serverMgr.mu.Unlock()
	}
	serverDir := a.GetServerDir()
	// 必须是严格子目录且解析符号链接后仍在根内，防止配置被改成根目录本身
	// 或指向外部的链接，导致 RemoveAll 清空所有服务器 / 删除越界路径。
	if !isStrictSubdir(serverDir, cfg.ServerDir) {
		return fmt.Errorf("服务器目录路径不安全（必须是服务器根目录的子目录），拒绝删除")
	}
	return os.RemoveAll(cfg.ServerDir)
}
