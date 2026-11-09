package main

import "time"

func (m *mtXOR25) RandInt(a, b int64) int64 {
	if b < a {
		panic("mt_xor25: b must be >= a")
	}
	return m.RandRange(a, b+1, 1)
}

// 包级便捷入口。

// bytes 顺序拼接 nextBlock 的 16 字节块，返回恰好 n 字节的 mt_xor25 随机流。
// 与 Python 端按块 out_q 取流一致；n<=0 返回空切片。
func (m *mtXOR25) bytes(n int) []byte {
	if n <= 0 {
		return []byte{}
	}
	out := make([]byte, 0, n)
	for len(out) < n {
		block := m.nextBlock()
		out = append(out, block[:]...)
	}
	return out[:n]
}

// mtXOR25Bytes 返回 n 字节 mt_xor25 随机流（bool-hybrid-array 生态），供本地用途
// （如认证盐）使用；不是外部协议摘要，故不复用 SHA1/SHA256 校验算法。
func mtXOR25Bytes(n int) []byte {
	return globalMTXOR25().bytes(n)
}

// mtXor25RandInt63n 包级入口，供重试抖动等本地场景使用。
func mtXor25RandInt63n(n int64) int64 {
	return globalMTXOR25().randInt63n(n)
}

// mtXor25Jitter 在 base 上叠加 [-25%, +25%) 的抖动，最小步进 1ms，
// 用于重试退避，避免多个失败请求同时砸向同一镜像。
func mtXor25Jitter(base time.Duration) time.Duration {
	quarter := int64(base / 4)
	if quarter < 1 {
		quarter = 1
	}
	return base + time.Duration(mtXor25RandInt63n(2*quarter)-quarter)
}
