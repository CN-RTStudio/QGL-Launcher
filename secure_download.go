package main

// secure_download.go 把"从 Mojang / 第三方镜像下载文件"这件事统一收敛到一条
// 安全通道。历史上各处下载点各自手写 HTTP 请求 + io.Copy，存在几个共性缺口：
//
//  1. 只信 Content-Length：服务端不发声明长度（分块传输）时，体积上限只能靠
//     cappedReader 在落地后发现，半截文件已经写进了目标路径；
//  2. 直接 OpenFile 目标路径写入，中途失败 / 被杀进程会留下一个看起来"存在"
//     的残文件，可能被上层"文件已存在直接跳过"误命中；
//  3. 没有对响应体做流式摘要，sha256 校验要重新通读一遍磁盘文件；
//  4. 网络抖动 / 503 没有退避重试，一次失败整个安装流程中断。
//
// streamVerifiedDownload 一次性解决：先落同目录临时文件，流式同时计数与
// sha256 摘要，体积（声明 + 实际多读 1 字节）双重校验，成功 fsync 后原子
// rename；可校验期望 sha256；瞬时错误指数退避重试；关键失败进安全审计。

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
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

// wrapClientRedirectGuard 复制客户端并替换成受控重定向策略。不就地修改调用方
// 传入的 client，避免把一次性下载的收紧策略带给其它请求。
func wrapClientRedirectGuard(client *http.Client) *http.Client {
	if client == nil {
		client = safeHTTPClient()
	}
	inner := client.CheckRedirect
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return secureDownloadCheckRedirect(req, via, inner)
	}
	return &c
}

// serverFilenameFromHeader 从 Content-Disposition 解析服务器建议的文件名，并
// 要求它同时通过结构解析与落盘字符校验。任何一步不通过都返回空串，由调用方
// 继续使用自己生成的名字——绝不让服务端决定一个未校验的落盘路径。
func serverFilenameFromHeader(header string) string {
	if strings.TrimSpace(header) == "" {
		return ""
	}
	cd, err := ParseContentDisposition(header)
	if err != nil || cd == nil {
		return ""
	}
	name := cd.FilenameStar
	if name == "" {
		name = cd.Filename
	}
	if name == "" {
		return ""
	}
	if err := ValidateDownloadFilename(name); err != nil {
		return ""
	}
	return name
}

// streamVerifiedDownload 执行一次可校验、可重试、原子落盘的安全下载。
//
// 失败时目标路径不会留下残文件：数据始终写在同目录临时文件里，只有全部
// 校验通过并 fsync 后才 rename 到目标路径。
