package main

import (
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
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
	sizes  map[string]int64             // fileURL -> Modrinth 声明的字节数
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

// verifyModDownloaded 用登记的期望值校验刚下载完的临时文件。
// 优先全长 sha512，缺失再退 sha1（Modrinth 协议允许只给其一）；
// 同时核对文件大小是否和声明一致。都没有登记则跳过（兼容老版本 API）。
func verifyModDownloaded(destPath, fileURL string) error {
	state := inspectRegularFile(destPath)
	if !state.Exists {
		return os.ErrNotExist
	}
	if !state.trustable() {
		return fmt.Errorf("%s", describeUntrustedFile(state, destPath))
	}

	hashes, wantSize, registered := modExpect.lookup(fileURL)
	if !registered {
		return nil
	}
	if wantSize > 0 && state.Size != wantSize {
		err := fmt.Errorf("文件大小不匹配：Modrinth 声明 %d 字节，实际 %d 字节（可能被截断或替换）",
			wantSize, state.Size)
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
		got, err := digestFileHex(f, sha512.New)
		if err != nil {
			return err
		}
		if !equalHexDigest(got, want) {
			err := fmt.Errorf("sha512 校验失败（可能下载被篡改）: got %s want %s", got, want)
			recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
				"modverify", "sha512 校验失败："+fileURL)
			return err
		}
		return nil
	}

	if want, ok := hashes["sha1"]; ok && want != "" {
		got, err := digestFileHex(f, sha1.New)
		if err != nil {
			return err
		}
		if !equalHexDigest(got, want) {
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
