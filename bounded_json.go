package main

// bounded_json.go 统一"从外部 HTTP(S) 接口拉一个 JSON 元数据文件"的读取方式。
//
// 版本清单、版本 JSON、资产索引这些接口历史上各自手写：
//
//	resp, _ := client.Get(u)
//	body, _ := io.ReadAll(io.LimitReader(resp.Body, 上限))
//	json.Unmarshal(body, &v)
//
// 这种写法有几个共性问题：
//
//  1. LimitReader 只是"最多读 N 字节"，服务端真返回超过 N 时，前 N 字节
//     仍会被 json.Unmarshal——要么碰巧解析出一个被截断的对象静默采用，
//     要么报一个与"体积超限"无关的语法错误，调用方无法区分攻击与抖动；
//  2. 不校验 Content-Type：一个被劫持的镜像可以把 HTML 错误页 / 任意二进制
//     当 JSON 回给我们（Unser 失败时只表现为语法错误，没有安全事件）；
//  3. 5xx / 连接重置没有退避重试；
//  4. 没有 context，取消下载任务时正在进行的元数据请求仍然占着连接。
//
// fetchJSONBounded 把这些收口：HTTPS 强制、多读 1 字节判定超限（超限是
// fatal，绝不 Unmarshal 截断体）、媒体类型白名单、瞬时错误指数退避、
// 全程 context；关键拒绝写安全审计。
//
// 另有一类 JSON 来自本地磁盘（versions/<id>/<id>.json、options、资产索引缓存）。
// 它们不走网络，但威胁类似：这些文件可被第三方启动器/模组/被入侵的镜像提前写坏，
// 历史调用方直接 os.ReadFile 整体读入再 Unmarshal，一个被塞成 GB 级的“json”同样
// 会让启动器 OOM。readLocalJSONBounded 用同一套“多读 1 字节判定超限、超限不
// Unmarshal”语义收口本地读取。

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	errJSONFetchTooLarge     = errors.New("JSON 响应体积超过安全上限")
	errJSONFetchBadType      = errors.New("JSON 响应 Content-Type 不被允许")
	errJSONFetchNoLimit      = errors.New("拉取 JSON 必须指定正的体积上限")
	errJSONFetchNoSuccessful = errors.New("全部 JSON 源地址都获取失败")

	// jsonFetchBackoffBase 是 5xx 重试的基础退避；设为变量而非常量，便于测试缩短等待。
	jsonFetchBackoffBase = 500 * time.Millisecond
)

const (
	jsonFetchDefaultAttempts = 3
	jsonFetchBufSize         = 64 * 1024
	jsonFetchMaxContentType  = 256

	// jsonLocalDefaultMaxBytes 是“本地版本/资产 JSON”读取的默认体积上限（64MiB）。
	// 正常版本 JSON（含 Forge 这类带大量库条目的）也就几 MiB，给 64MiB 是刻意取宽，
	// 只拦被恶意塞成 GB 级、会把进程内存打爆的“json”文件（炸磁盘/内存才拦）。
	jsonLocalDefaultMaxBytes int64 = 64 << 20
)

// jsonFetchOptions 控制一次有界 JSON 拉取。
type jsonFetchOptions struct {
	MaxBytes        int64        // 必填：响应体硬上限，超出即 fatal
	Attempts        int          // 可空：<=0 取 jsonFetchDefaultAttempts
	UserAgent       string       // 可空：为空不覆盖 UA
	Client          *http.Client // 可空：为空用 safeHTTPClient()
	AllowMediaTypes []string     // 可空：非空时响应媒体类型必须命中其一（小写比较）
	SourceLabel     string       // 可空：审计日志中标识这份元数据的名字，如 "版本清单"
}

// parseMediaType 从 Content-Type 头取 media type（去掉 ;charset=...），
// 并对异常超长头做收口，防止审计日志被撑大。
func parseMediaType(header string) string {
	h := strings.TrimSpace(header)
	if len(h) > jsonFetchMaxContentType {
		h = h[:jsonFetchMaxContentType]
	}
	if i := strings.IndexByte(h, ';'); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

// mediaTypeAllowed 判断实际媒体类型是否命中白名单。白名单为空表示不校验。
func mediaTypeAllowed(actual string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, m := range allow {
		if actual == strings.ToLower(strings.TrimSpace(m)) {
			return true
		}
	}
	return false
}

// readBoundedBody 从 rc 最多读取 maxBytes+1 字节。
// 返回 errJSONFetchTooLarge 表示实际数据超过上限；调用方不得使用 data。
func readBoundedBody(rc io.Reader, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(rc, maxBytes+1)
	buf := make([]byte, 0, 256)
	chunk := make([]byte, jsonFetchBufSize)
	for {
		n, err := limited.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if int64(len(buf)) > maxBytes {
				return nil, errJSONFetchTooLarge
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}
