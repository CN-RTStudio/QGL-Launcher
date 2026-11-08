package main

// contentdisposition.go —— RFC 6267 Content-Disposition 下载文件名的有界解析与
// 安全决策内核。
//
// 现状：下载/镜像流程此前没有结构化解析 Content-Disposition，文件名来源若被
// 直接信任会产生：
//   1. 路径穿越：filename="../../etc/passwd"、filename*=UTF-8''..%2f..%2fx；
//   2. 盘符 / UNC：filename="C:\x.jar"、"\\server\share\y"；
//   3. Windows 保留设备名：CON、PRN、AUX、NUL、COM1、LPT1（nameguard 已含判定，
//      这里复用，不重复声明）；
//   4. 参数混淆：同时给 filename 与 filename*（RFC 规定 filename* 优先），用
//      filename* 绕过对 filename 的粗过滤；
//   5. 注入：参数里塞控制字符 / 引号转义 / 伪造扩展名 "x.jar\x00.txt"；
//   6. 字符集伪装：filename* 声明非 UTF-8 字符集或百分号解码出非法 UTF-8。
//
// 本模块只做“解析 + 安全判定”，不拼磁盘路径；最终落盘命名仍交由 nameguard 的
// SafeModFileName 等落盘函数。手写有界参数解析，不依赖正则。

import "strings"

const (
	CDReasonEmpty           = "cd-empty-header"
	CDReasonMalformed       = "cd-malformed-parameter"
	CDReasonUnsafeCharset   = "cd-unsupported-filename-star-charset"
	CDReasonBadPercent      = "cd-bad-percent-encoding"
	CDReasonNoFilename      = "cd-no-filename"
	CDReasonPathSeparator   = "cd-filename-contains-path-separator"
	CDReasonDriveOrUNC      = "cd-filename-drive-or-unc"
	CDReasonReservedDevice  = "cd-filename-reserved-device"
	CDReasonControlChar     = "cd-filename-control-character"
	CDReasonTraversal       = "cd-filename-path-traversal"
	CDReasonNameTooLong     = "cd-filename-too-long"
	CDReasonDotOrSpace      = "cd-filename-dot-or-space-only"
	CDReasonLeadingDotSpace = "cd-filename-leading-dot-space"
	CDReasonNullByte        = "cd-filename-null-byte"
	CDReasonAlternateStream = "cd-filename-alternate-data-stream"
	CDReasonForbiddenChar   = "cd-filename-forbidden-character"
	CDReasonInvisibleRune   = "cd-filename-invisible-rune"
	CDReasonDuplicateParam  = "cd-duplicate-filename-parameter"
)

const cdMaxHeaderLen = 8192
const cdMaxFilenameLen = 255

// CDResult 是解析结果。
type CDResult struct {
	Disposition  string            // attachment / inline / form-data / 扩展记号（小写）
	Filename     string            // filename 参数（token 或 quoted-string 解码后）
	FilenameStar string            // filename* 参数（百分号解码后，已校验 UTF-8）
	Params       map[string]string // 其余参数（小写键）
}

// ParseContentDisposition 解析单个 Content-Disposition 头值。
func ParseContentDisposition(header string) (*CDResult, error) {
	if len(header) > cdMaxHeaderLen {
		return nil, cdErr(CDReasonMalformed)
	}
	h := strings.TrimSpace(header)
	if h == "" {
		return nil, cdErr(CDReasonEmpty)
	}

	p := &cdParser{s: h}
	disp := p.readToken()
	if disp == "" {
		return nil, cdErr(CDReasonMalformed)
	}
	res := &CDResult{Disposition: strings.ToLower(disp), Params: map[string]string{}}
	seenFilenameParam := map[string]bool{}

	for {
		p.skipOWS()
		if p.atEnd() {
			break
		}
		if p.peek() != ';' {
			return nil, cdErr(CDReasonMalformed)
		}
		p.next() // 消费 ';'
		p.skipOWS()
		key := p.readToken()
		if key == "" {
			return nil, cdErr(CDReasonMalformed)
		}
		p.skipOWS()
		if p.atEnd() || p.peek() != '=' {
			return nil, cdErr(CDReasonMalformed)
		}
		p.next()
		p.skipOWS()
		val, ok := p.readValue()
		if !ok {
			return nil, cdErr(CDReasonMalformed)
		}
		lk := strings.ToLower(key)
		switch lk {
		case "filename", "filename*":
			// 同一个参数名重复出现属于参数混淆：后一个值会覆盖前一个，服务端与
			// 中间缓存可能各取其一，最终落盘名与校验名可能不是同一个。filename
			// 与 filename* 并存是 RFC 允许的降级写法，不算重复。
			if seenFilenameParam[lk] {
				return nil, cdErr(CDReasonDuplicateParam)
			}
			seenFilenameParam[lk] = true
			if lk == "filename" {
				res.Filename = val
				continue
			}
			decoded, err := decodeFilenameStar(val)
			if err != nil {
				return nil, err
			}
			res.FilenameStar = decoded
		default:
			if _, exists := res.Params[lk]; !exists {
				res.Params[lk] = val
			}
		}
	}
	return res, nil
}

// PreferredFilename 按 RFC 6267 优先返回 filename*，否则 filename；都没有返回空。
func (r *CDResult) PreferredFilename() string {
	if r == nil {
		return ""
	}
	if r.FilenameStar != "" {
		return r.FilenameStar
	}
	return r.Filename
}

type cdParser struct {
	s string
	i int
}

func (p *cdParser) atEnd() bool { return p.i >= len(p.s) }
func (p *cdParser) peek() byte {
	if p.atEnd() {
		return 0
	}
	return p.s[p.i]
}
func (p *cdParser) next() byte {
	if p.atEnd() {
		return 0
	}
	c := p.s[p.i]
	p.i++
	return c
}
