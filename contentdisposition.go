package main

import (
	"strings"
)

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
