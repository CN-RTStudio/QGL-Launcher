package main

import (
	"errors"
	"fmt"
	"net/http"
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

// secureDownloadOptions 控制一次安全下载。
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

// secureDownloadResult 是一次成功下载的回执。
type secureDownloadResult struct {
	Bytes      int64  // 实际落盘字节数
	SHA256     string // 实际流式 sha256（小写十六进制）
	Attempts   int    // 实际使用的尝试次数（1 表示首次成功）
	ServerName string // 可空：Content-Disposition 里通过安全校验的文件名
}

// secureDownloadCheckRedirect 在 Download 客户端上叠加逐跳校验：先复用全局
// safeCheckRedirect 的 https-only / 私网拦截，再用 redirchain 复核 userinfo 与
// 跳转环。调用方自带的 CheckRedirect（如 Mod 下载白名单）仍会先行执行，本函数
// 只做收紧，不放松任何既有规则。
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
