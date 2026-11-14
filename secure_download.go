package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"
)

var (
	errSecureDownloadTooLarge    = errors.New("下载体积超过安全上限")
	errSecureDownloadBadHash     = errors.New("下载文件 sha256 校验失败")
	errSecureDownloadBadSize     = errors.New("下载文件实际体积与声明不符")
	errSecureDownloadStatus      = errors.New("下载返回了非成功状态码")
	errSecureDownloadNoLimit     = errors.New("安全下载必须指定正的体积上限")
	errSecureDownloadBadRedirect = errors.New("下载重定向链被安全策略拒绝")
	errSecureDownloadBadName     = errors.New("服务器给出的下载文件名不可安全落盘")
)

const (
	secureDownloadDefaultAttempts = 3
	secureDownloadBufSize         = 64 * 1024
	secureDownloadBackoffBase     = 500 * time.Millisecond
)

type secureDownloadOptions struct {
	MaxBytes       int64                       // 必填：声明与实际体积的共同硬上限
	ExpectedSHA256 string                      // 可空：非空时必须与流式摘要一致（小写十六进制）
	Attempts       int                         // 可空：<=0 时取 secureDownloadDefaultAttempts
	UserAgent      string                      // 可空：为空则不覆盖
	Client         *http.Client                // 可空：为空用 safeHTTPClient()
	Progress       func(received, total int64) // 可空：每读到一批数据回调一次
	MarkWebOrigin  bool                        // 可空：Windows 上落盘后写入 MOTW（ZoneId=3 Internet）
	ReferrerURL    string                      // 可空：MOTW 的 ReferrerUrl
}
type secureDownloadResult struct {
	Bytes      int64  // 实际落盘字节数
	SHA256     string // 实际流式 sha256（小写十六进制）
	Attempts   int    // 实际使用的尝试次数（1 表示首次成功）
	ServerName string // 可空：Content-Disposition 里通过安全校验的文件名
}

func secureDownloadCheckRedirect(req *http.Request, via []*http.Request, inner func(*http.Request, []*http.Request) error) error {
	if inner != nil {
		if err := inner(req, via); err != nil {
			return err
		}
	}
	if err := safeCheckRedirect(req, via); err != nil {
		return err
	}
	if len(via) == 0 {
		return nil
	}
	chain, err := newRedirectChain(via[0].URL.String(), defaultRedirectLimits())
	if err != nil {
		return fmt.Errorf("%w: 无法记录入口 URL", errSecureDownloadBadRedirect)
	}
	for _, hop := range via[1:] {
		if ok, reason := chain.Decide(hop.URL.String(), nil); !ok {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
				"secure-download", "重定向中间跳被拒绝: "+reason+" -> "+hop.URL.String())
			return fmt.Errorf("%w: %s", errSecureDownloadBadRedirect, reason)
		}
	}
	if ok, reason := chain.Decide(req.URL.String(), nil); !ok {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"secure-download", "重定向目标被拒绝: "+reason+" -> "+req.URL.String())
		return fmt.Errorf("%w: %s", errSecureDownloadBadRedirect, reason)
	}
	return nil
}

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

// attemptSecureDownload 是单次尝试。返回 fatal=true 表示错误不可重试。
