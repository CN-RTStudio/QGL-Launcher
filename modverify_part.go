package main

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
)

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
