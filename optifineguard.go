package main

// optifineguard.go —— OptiFine 下载地址与安装包文件名校验内核。
//
// 背景：
//   OptiFine 发行不经过 Maven 中心，常见来源是 optifine.net 官方页与各种镜像站。
//   启动器若直接把用户填写的下载地址 / 文件名拼进下载任务，攻击面包括：
//     1) 镜像地址投毒：host 白名单外的"镜像"（或后缀欺骗域名）返回被篡改的 jar，
//        供应链在下载起点就被污染；
//     2) 文件名注入：安装包名含路径分隔符/控制字符/超长，落盘时越界写；
//     3) 后缀伪装：把 zip/exe/scr 伪装成 .jar 放行，或把 jar 伪装成其它扩展名，
//        让后续的 jar 校验（哈希/签名）被绕过。
//   本模块只做地址与文件名的形态校验，真正的字节级校验仍在下载链路中完成。

import (
	"errors"
	"net/url"
	"strings"
)

// OptiFineLimits 限定 OptiFine 输入边界。
type OptiFineLimits struct {
	MaxUrlRunes   int
	MaxNameRunes  int
}

func (l *OptiFineLimits) withDefaults() OptiFineLimits {
	if l == nil {
		l = &OptiFineLimits{}
	}
	out := *l
	if out.MaxUrlRunes <= 0 {
		out.MaxUrlRunes = 2048
	}
	if out.MaxNameRunes <= 0 {
		out.MaxNameRunes = 160
	}
	return out
}

// optifineHosts 是允许的 OptiFine 下载来源主机。
var optifineHosts = []string{
	"optifine.net",
	"optifine.cn",
	"optifine.tk",
	"mcimg.net",
	"download.optifine.net",
}

// ValidateOptifineUrl 校验下载 URL：https + 白名单主机 + 无控制字符/无 query 注入。
func ValidateOptifineUrl(raw string, lim OptiFineLimits) (string, error) {
	d := lim.withDefaults()
	if len([]rune(raw)) > d.MaxUrlRunes {
		return "", errors.New("optifine url too long")
	}
	if hasControlCharStr(raw) {
		return "", errors.New("optifine url contains control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("optifine url must be https")
	}
	if u.Scheme != "https" {
		return "", errors.New("optifine url must be https")
	}
	if u.User != nil {
		return "", errors.New("optifine url must not contain userinfo")
	}
	hl := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if hl == "" {
		return "", errors.New("optifine url host not allowed")
	}
	matched := false
	for _, allowed := range optifineHosts {
		if hl == allowed || strings.HasSuffix(hl, "."+allowed) {
			matched = true
			break
		}
	}
	if !matched {
		return "", errors.New("optifine url host not allowed")
	}
	return raw, nil
}

// ValidateOptifineFileName 校验安装包文件名：单段、限长、无控制字符、
// 必须以 .jar 结尾（OptiFine 安装包统一为 jar，防止伪装扩展名）。
func ValidateOptifineFileName(name string, lim OptiFineLimits) (string, error) {
	d := lim.withDefaults()
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errors.New("optifine file name is empty")
	}
	if len([]rune(trimmed)) > d.MaxNameRunes {
		return "", errors.New("optifine file name too long")
	}
	if hasControlCharStr(trimmed) {
		return "", errors.New("optifine file name contains control characters")
	}
	if strings.ContainsAny(trimmed, `/\`) || strings.Contains(trimmed, "..") {
		return "", errors.New("optifine file name must be a single path segment")
	}
	if !strings.HasSuffix(strings.ToLower(trimmed), ".jar") {
		return "", errors.New("optifine package must be a .jar file")
	}
	base := strings.TrimSuffix(trimmed, ".jar")
	if base == "" || strings.HasPrefix(base, ".") {
		return "", errors.New("optifine file name has invalid base")
	}
	return trimmed, nil
}

// ClassifyOptifineUrl 返回一个简短的分类描述，供日志/事件使用。
func ClassifyOptifineUrl(raw string) string {
	if raw == "" {
		return "optifine-url-empty"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return "optifine-url-non-https"
	}
	if u.Path == "" || u.Path == "/" {
		return "optifine-url-no-path"
	}
	return "optifine-url-ok"
}

// SummarizeOptifineError 把校验错误压成一行可读文本。
func SummarizeOptifineError(err error) string {
	if err == nil {
		return "optifine check ok"
	}
	return "optifine check rejected: " + err.Error()
}
