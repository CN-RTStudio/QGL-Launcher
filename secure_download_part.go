package main

import (
	"context"
	"fmt"
	"path/filepath"
)

func streamVerifiedDownload(ctx context.Context, url, destPath string, opts secureDownloadOptions) (*secureDownloadResult, error) {
	if !isHTTPSURL(url) {
		return nil, fmt.Errorf("拒绝不安全的下载 URL（非 HTTPS）: %s", url)
	}
	// 短链 / 重定向预检：任何下载出发前先过 shortlinkguard。非短链 URL 只做
	// 协议与 userinfo 校验；短链 URL 追加目标主机私网判定（解析器走真实 DNS，
	// 域名命中私网 / 回环 / 链路本地即拒绝）。失败视为不可重试的硬错误。
	preflighted, err := preflightDownloadURL(url, nil)
	if err != nil {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"secure-download", "下载 URL 预检拒绝: "+err.Error())
		return nil, err
	}
	url = preflighted
	if opts.MaxBytes <= 0 {
		return nil, errSecureDownloadNoLimit
	}
	attempts := opts.Attempts
	if attempts <= 0 {
		attempts = secureDownloadDefaultAttempts
	}
	client := opts.Client
	if client == nil {
		client = safeHTTPClient()
	}
	client = wrapClientRedirectGuard(client)
	dir := filepath.Dir(destPath)
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	// 目标路径已被符号链接 / 特殊文件占据时拒绝：rename 会跟随替换普通文件，
	// 但先挡住异常路径，避免被诱导把文件写到重解析点上。
	if bad, err := isSymlinkOrSpecial(destPath); err != nil {
		return nil, fmt.Errorf("检查目标路径失败: %w", err)
	} else if bad {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"secure-download", "目标路径是符号链接或特殊文件，拒绝下载写入: "+destPath)
		return nil, fmt.Errorf("拒绝写入符号链接或非普通文件: %s", destPath)
	}

	var res *secureDownloadResult
	// fatal 表示重试没有意义（超限 / 哈希不符 / 4xx），由内核直接返回。
	used, err := runWithRetry(ctx, attempts, secureDownloadBackoffBase, func() (bool, error) {
		r, fatal, e := attemptSecureDownload(ctx, client, url, destPath, opts)
		res = r
		return fatal, e
	})
	if err != nil {
		return nil, err
	}
	res.Attempts = used
	return res, nil
}
