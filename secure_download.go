package main

import (
	"errors"
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
