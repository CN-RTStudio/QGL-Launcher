package main

import (
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
	"os"
	"strings"
)

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
