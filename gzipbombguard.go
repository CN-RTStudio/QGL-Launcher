package main

// gzipbombguard.go —— HTTP 响应 Content-Encoding 解压炸弹流式守卫。
//
// 背景：
//   archivebombguard 管的是落盘压缩包；这里管的是"在线响应体即时解压"。服务器（或被 MITM 的响应）
//   可对一个极小 body 声明 Content-Encoding: gzip/deflate/br，解压后膨胀成 GB 级文本，直接打进内存：
//     - 超高压缩比（几 KB -> 几 GB，典型 gzip bomb / "十亿零"）；
//     - 解压后总量超过上限，或单轮读取产出远超本轮压缩输入；
//     - 声明的 Content-Length 很小却无限吐出解压字节（声明与实际不符，绕过按压缩长度做的配额）；
//     - 多层嵌套编码（gzip,gzip,...）反复膨胀；
//     - 解压中途仍持续高 ratio（不是正常资源头部的短暂抖动）。
//   本模块是一个纯数值状态机：调用方每把一批"压缩输入字节数/解压产出字节数"喂进来，守卫据此判定
//   是否应立即中止解压。不执行任何解压、不依赖具体编码库，纯整数运算，不使用正则。

const (
	GZBReasonRatioExceeded          = "gzipbomb-decompression-ratio-exceeded"
	GZBReasonTotalExceeded          = "gzipbomb-decompressed-total-exceeded"
	GZBReasonBurstExceeded          = "gzipbomb-single-read-burst-too-large"
	GZBReasonDeclaredLengthMismatch = "gzipbomb-declared-length-vs-output-mismatch"
	GZBReasonNestedEncoding         = "gzipbomb-nested-content-encoding"
	GZBReasonSustainedExpansion     = "gzipbomb-sustained-high-expansion"
	GZBReasonNegativeDelta          = "gzipbomb-negative-byte-delta"
)

// GZBPolicy 设定解压闸门。
type GZBPolicy struct {
	MaxTotalBytes          int64 // 解压后总产出上限
	MaxCompressionRatio    int   // 累积压缩比上限（产出/压缩输入）
	MaxSingleBurstBytes    int64 // 单批产出上限
	SustainedWindowStreaks int   // 连续多少批高膨胀判定为持续
	SustainedRatio         int   // 单批膨胀比阈值
	MaxEncodingLayers      int   // Content-Encoding 允许层数
}

// GZBFinding 记录一处解压炸弹风险。
type GZBFinding struct {
	Reason string
	Detail string
}

// DefaultGZBPolicy 默认 256MiB、综合比 200、单批 16MiB、连续 4 批/比 500、1 层编码。
func DefaultGZBPolicy() GZBPolicy {
	return GZBPolicy{
		MaxTotalBytes:          256 * 1024 * 1024,
		MaxCompressionRatio:    200,
		MaxSingleBurstBytes:    16 * 1024 * 1024,
		SustainedWindowStreaks: 4,
		SustainedRatio:         500,
		MaxEncodingLayers:      1,
	}
}

// GZBMonitor 是一次响应解压的流式监控器。
type GZBMonitor struct {
	policy       GZBPolicy
	compressedIn int64
	producedOut  int64
	highStreak   int
	declaredLen  int64 // 响应头里的压缩 Content-Length，0 表示未知
	aborted      bool
	abortReason  string
}

// NewGZBMonitor 创建监控器。declaredCompressedLength 取 Content-Length（压缩态长度）。
func NewGZBMonitor(policy GZBPolicy, declaredCompressedLength int64) *GZBMonitor {
	return &GZBMonitor{policy: policy, declaredLen: declaredCompressedLength}
}

// GZBCheckEncodingLayers 校验 Content-Encoding 层数（逗号分隔）。
func GZBCheckEncodingLayers(contentEncoding string, policy GZBPolicy) (safe bool, findings []GZBFinding) {
	ce := trimSpaceGZB(contentEncoding)
	if ce == "" {
		return true, nil
	}
	layers := 0
	for _, tok := range splitCommaGZB(ce) {
		if trimSpaceGZB(tok) != "" {
			layers++
		}
	}
	if layers > policy.MaxEncodingLayers {
		findings = append(findings, GZBFinding{Reason: GZBReasonNestedEncoding,
			Detail: itoaGZB(layers)})
	}
	return len(findings) == 0, findings
}

// Observe 喂入一批数据：compIn 为本批读入的压缩字节，produced 为解压产出字节。
// 返回是否继续安全；false 时 AbortReason() 给出原因。
