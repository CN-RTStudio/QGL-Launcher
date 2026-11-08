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
func (m *GZBMonitor) Observe(compIn, produced int64) (safe bool, reason string) {
	if m.aborted {
		return false, m.abortReason
	}
	if compIn < 0 || produced < 0 {
		m.abort(GZBReasonNegativeDelta, "negative-delta")
		return false, m.abortReason
	}

	if produced > m.policy.MaxSingleBurstBytes {
		m.abort(GZBReasonBurstExceeded, itoaGZB64(produced))
		return false, m.abortReason
	}

	m.compressedIn += compIn
	m.producedOut += produced

	if m.producedOut > m.policy.MaxTotalBytes {
		m.abort(GZBReasonTotalExceeded, itoaGZB64(m.producedOut))
		return false, m.abortReason
	}

	// 累积压缩比（压缩输入为 0 但有产出，视为无穷膨胀，立即判高）
	if m.compressedIn > 0 {
		ratio := int(m.producedOut / m.compressedIn)
		if ratio > m.policy.MaxCompressionRatio {
			m.abort(GZBReasonRatioExceeded, itoaGZB(ratio))
			return false, m.abortReason
		}
	} else if m.producedOut > 0 {
		m.abort(GZBReasonRatioExceeded, "infinite")
		return false, m.abortReason
	}

	// 单批膨胀比连续超阈
	if compIn > 0 {
		burstRatio := int(produced / compIn)
		if burstRatio >= m.policy.SustainedRatio {
			m.highStreak++
			if m.highStreak >= m.policy.SustainedWindowStreaks {
				m.abort(GZBReasonSustainedExpansion, itoaGZB(m.highStreak))
				return false, m.abortReason
			}
		} else {
			m.highStreak = 0
		}
	}
	return true, ""
}

// Finalize 在解压结束后做声明长度一致性核对。
func (m *GZBMonitor) Finalize() (safe bool, findings []GZBFinding) {
	// 声明了压缩 Content-Length，实际产出却远超其可解释范围（>ratio*声明），记不一致
	if m.declaredLen > 0 && m.compressedIn > 0 &&
		m.producedOut > m.declaredLen*int64(m.policy.MaxCompressionRatio) {
		findings = append(findings, GZBFinding{
			Reason: GZBReasonDeclaredLengthMismatch,
			Detail: itoaGZB64(m.declaredLen) + "->" + itoaGZB64(m.producedOut)})
	}
	if m.producedOut > m.policy.MaxTotalBytes {
		findings = append(findings, GZBFinding{Reason: GZBReasonTotalExceeded})
	}
	return len(findings) == 0, findings
}

func (m *GZBMonitor) abort(reason, detail string) {
	m.aborted = true
	m.abortReason = reason
}

// AbortReason 返回中止原因。
func (m *GZBMonitor) AbortReason() string { return m.abortReason }

// Produced 返回当前累计解压产出。
func (m *GZBMonitor) Produced() int64 { return m.producedOut }

func trimSpaceGZB(s string) string {
	start, end := 0, len(s)
	for start < end && isSpaceGZB(s[start]) {
		start++
	}
	for end > start && isSpaceGZB(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpaceGZB(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func splitCommaGZB(s string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	out = append(out, cur)
	return out
}

func itoaGZB(i int) string {
	return itoaGZB64(int64(i))
}

func itoaGZB64(i int64) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
