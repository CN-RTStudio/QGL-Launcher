package main

import (
	"net/http"
	"strings"
)

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
