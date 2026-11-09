package main

const (
	GZBReasonRatioExceeded          = "gzipbomb-decompression-ratio-exceeded"
	GZBReasonTotalExceeded          = "gzipbomb-decompressed-total-exceeded"
	GZBReasonBurstExceeded          = "gzipbomb-single-read-burst-too-large"
	GZBReasonDeclaredLengthMismatch = "gzipbomb-declared-length-vs-output-mismatch"
	GZBReasonNestedEncoding         = "gzipbomb-nested-content-encoding"
	GZBReasonSustainedExpansion     = "gzipbomb-sustained-high-expansion"
	GZBReasonNegativeDelta          = "gzipbomb-negative-byte-delta"
)

type GZBPolicy struct {
	MaxTotalBytes          int64 // 解压后总产出上限
	MaxCompressionRatio    int   // 累积压缩比上限（产出/压缩输入）
	MaxSingleBurstBytes    int64 // 单批产出上限
	SustainedWindowStreaks int   // 连续多少批高膨胀判定为持续
	SustainedRatio         int   // 单批膨胀比阈值
	MaxEncodingLayers      int   // Content-Encoding 允许层数
}
type GZBFinding struct {
	Reason string
	Detail string
}

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
