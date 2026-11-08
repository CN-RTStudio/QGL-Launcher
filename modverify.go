package main

// modverify.go 收口 Mod 下载链路上三件以前散落在 mod.go 里、且各有真实缺口的东西：
//
//  1. 期望值存储（哈希/大小）。旧实现是两个裸包级 map，登记动作发生在
//     downloadMutex 加锁之前，前端并发点两个“下载 Mod”就会触发 Go 运行时
//     fatal "concurrent map writes" 直接崩掉整个启动器；下载 goroutine 同时
//     还在无锁读这两个 map。这里用独立 RWMutex 收口全部读写。
//  2. 下载主机白名单。旧实现只校验 https://，被攻陷/伪造的 Modrinth 版本
//     元数据可以把文件 URL 指到任意外部主机，没有哈希的文件会被原样下载
//     进 mods 目录并随游戏执行。重定向跳转同样可能把官方主机甩到任意主机。
//  3. 符号链接安全落盘。O_CREATE 在目标已是符号链接时会顺着链接写穿到
//     链接指向的任意文件（mods 目录可被本地其它程序预置 .part 链接）。
//
// 外部协议要求的摘要算法（Modrinth 的 sha512/sha1）按协议保留，不替换。

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

// ===== 期望值存储（并发安全） =====

// modExpectationStore 保存“某个下载 URL 应该长什么样”的元数据：
// Modrinth 声明的哈希集合与文件大小。key 一律是下载 URL。
type modExpectationStore struct {
	mu     sync.RWMutex
	hashes map[string]map[string]string // fileURL -> 算法名(小写) -> 十六进制摘要(小写)
	sizes  map[string]int64            // fileURL -> Modrinth 声明的字节数
}

func newModExpectationStore() *modExpectationStore {
	return &modExpectationStore{
		hashes: map[string]map[string]string{},
		sizes:  map[string]int64{},
	}
}

// record 登记一个文件的期望哈希和大小。f 来自 Modrinth 版本元数据。
func (s *modExpectationStore) record(fileURL string, f ModFile) {
	if fileURL == "" {
		return
	}
	hashes := make(map[string]string, len(f.Hashes)+1)
	for k, v := range f.Hashes {
		if v != "" {
			hashes[strings.ToLower(k)] = strings.ToLower(v)
		}
	}
	// 老版本 API 可能只给顶层 sha1 字段，没有 hashes 表。
	if f.SHA1 != "" {
		if _, ok := hashes["sha1"]; !ok {
			hashes["sha1"] = strings.ToLower(f.SHA1)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(hashes) > 0 {
		s.hashes[fileURL] = hashes
	}
	if f.Size > 0 {
		s.sizes[fileURL] = f.Size
	}
}

// lookup 返回某 URL 的期望哈希（副本，调用方随便改）和期望大小。
// registered 表示该 URL 是否登记过任一期望值，行为对齐旧实现
// “没有期望值就不做完整性校验、不阻塞下载”的约定。
func (s *modExpectationStore) lookup(fileURL string) (hashes map[string]string, wantSize int64, registered bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	wantSize, hasSize := s.sizes[fileURL]
	src, hasHashes := s.hashes[fileURL]
	if hasHashes {
		hashes = make(map[string]string, len(src))
		for k, v := range src {
			hashes[k] = v
		}
	}
	registered = hasHashes || (hasSize && wantSize > 0)
	return hashes, wantSize, registered
}

// delete 清掉某 URL 的期望值。下载流程结束（成功落盘 / 校验失败 / 跳过）
// 后都应调用，避免 map 随下载历史无限增长。
func (s *modExpectationStore) delete(fileURL string) {
	s.mu.Lock()
	delete(s.hashes, fileURL)
	delete(s.sizes, fileURL)
	s.mu.Unlock()
}

// modExpect 是包级唯一实例。
var modExpect = newModExpectationStore()

// verifyModDownloaded 用登记的期望值校验刚下载完的临时文件。
// 优先全长 sha512，缺失再退 sha1（Modrinth 协议允许只给其一）；
// 同时核对文件大小是否和声明一致。都没有登记则跳过（兼容老版本 API）。
func verifyModDownloaded(destPath, fileURL string) error {
	info, err := os.Stat(destPath)
	if err != nil {
		return err
	}

	hashes, wantSize, registered := modExpect.lookup(fileURL)
	if !registered {
		return nil
	}
	if wantSize > 0 && info.Size() != wantSize {
		err := fmt.Errorf("文件大小不匹配：Modrinth 声明 %d 字节，实际 %d 字节（可能被截断或替换）",
			wantSize, info.Size())
		recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
			"modverify", err.Error()+"："+fileURL)
		return err
	}
	if len(hashes) == 0 {
		return nil
	}

	f, err := os.Open(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if want, ok := hashes["sha512"]; ok && want != "" {
		h := sha512.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		got := hex.EncodeToString(h.Sum(nil))
		if got != want {
			err := fmt.Errorf("sha512 校验失败（可能下载被篡改）: got %s want %s", got, want)
			recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
				"modverify", "sha512 校验失败："+fileURL)
			return err
		}
		return nil
	}

	if want, ok := hashes["sha1"]; ok && want != "" {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		h := sha1.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		got := hex.EncodeToString(h.Sum(nil))
		if got != want {
			err := fmt.Errorf("sha1 校验失败（可能下载被篡改）: got %s want %s", got, want)
			recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
				"modverify", "sha1 校验失败："+fileURL)
			return err
		}
		return nil
	}
	return nil
}

// ===== 下载主机白名单 =====

// allowedModDownloadHosts 是 Mod 文件下载允许出现的主机后缀白名单。
// 官方源：Modrinth CDN/API、CurseForge CDN；镜像源：mcimirror。
// 用“等于或为其子域”的方式匹配，cdn.modrinth.com.evil.com 这类
// 拼后缀的视觉混淆主机不会被放行。
var allowedModDownloadHosts = []string{
	"cdn.modrinth.com",
	"api.modrinth.com",
	"edge.forgecdn.net",
	"mediafilez.forgecdn.net",
	"mod.mcimirror.top",
}

// modHostAllowed 判断主机（不含端口）是否在 Mod 下载白名单内。
func modHostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, allowed := range allowedModDownloadHosts {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

// validateModDownloadURL 校验 Mod 下载 URL：
// 只允许 https、禁止 userinfo 视觉混淆、只允许默认 443 端口、主机必须在白名单内。
func validateModDownloadURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("空的下载 URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("下载 URL 解析失败: %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("不安全的下载 URL（非 HTTPS）: scheme=%q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("下载 URL 不允许携带用户信息(userinfo): %s", u.Host)
	}
	if port := u.Port(); port != "" && port != "443" {
		return fmt.Errorf("下载 URL 只允许 443 端口，收到 %q", port)
	}
	if !modHostAllowed(u.Hostname()) {
		return fmt.Errorf("下载主机 %q 不在 Mod 下载白名单内", strings.ToLower(u.Hostname()))
	}
	return nil
}

// modDownloadCheckRedirect 是 Mod 文件下载专用的重定向策略：
// 每一跳都必须是 https、不能进内网/回环（复用全局 safeCheckRedirect 的判定）、
// 主机还必须继续停留在 Mod 下载白名单内，且跳转次数受 maxRedirects 限制。
func modDownloadCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return http.ErrUseLastResponse
	}
	next := req.URL
	if !isHTTPSURL(next.String()) {
		return errDenyInsecureRedirect
	}
	if isPrivateDest(next.String()) {
		return errDenyPrivateRedirect
	}
	if !modHostAllowed(next.Hostname()) {
		return fmt.Errorf("重定向到非白名单下载主机被拒绝: %s", strings.ToLower(next.Hostname()))
	}
	return nil
}

// newModDownloadClient 返回用于下载 Mod 文件的 HTTP 客户端。
// 与 safeHTTPClient 的区别：
//   - 不设 30 秒总超时：大体积整合包 Mod 走慢网超过 30 秒很正常，旧代码直接
//     用 safeHTTPClient 下载文件会被整体掐断；体积上限由 MaxBytesReader 兜底，
//     不需要靠总超时防炸磁盘；
//   - 重定向每一跳都强制主机白名单（见 modDownloadCheckRedirect）。
func newModDownloadClient() *http.Client {
	c := safeHTTPClient()
	c.Timeout = 0
	c.CheckRedirect = modDownloadCheckRedirect
	return c
}

// ===== 符号链接安全落盘 =====

// isSymlink 报告路径当前是否为符号链接；路径不存在时返回 false。
func isSymlink(p string) bool {
	fi, err := os.Lstat(p)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}

// openSecurePartFile 创建/截断下载临时文件。写入前用 Lstat 确认它不是
// 预置的符号链接，避免顺着链接写穿到 mods 目录之外的任意文件。
func openSecurePartFile(partPath string) (*os.File, error) {
	if isSymlink(partPath) {
		return nil, fmt.Errorf("临时文件路径是符号链接，拒绝写入: %s", partPath)
	}
	return os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
}

// finalizeDownloadFile 在完整性校验通过后把临时文件原子改名为最终文件。
// 最终路径若已被调包成符号链接同样拒绝落盘。
func finalizeDownloadFile(partPath, destPath string) error {
	if isSymlink(destPath) {
		os.Remove(partPath)
		return fmt.Errorf("目标路径是符号链接，拒绝落盘: %s", destPath)
	}
	if err := os.Rename(partPath, destPath); err != nil {
		os.Remove(partPath)
		return fmt.Errorf("重命名临时文件失败: %v", err)
	}
	return nil
}
