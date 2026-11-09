package main

import (
	"encoding/binary"
	"math/big"
	"time"
)

func (m *mtXOR25) randInt63n(n int64) int64 {
	if n <= 0 {
		panic("mt_xor25: n must be positive")
	}
	threshold := uint64(1<<63) - uint64(1<<63)%uint64(n)
	for {
		block := m.nextBlock()
		v := binary.BigEndian.Uint64(block[:8]) >> 1 // 取正整数
		if v < threshold {
			return int64(v % uint64(n))
		}
	}
}

// Uniform 对照 Python XOR25_Generator.uniform：用 1024bit 随机数映射到 [low,high)。
func (m *mtXOR25) Uniform(low, high float64) float64 {
	if high <= low {
		return low
	}
	r := m.GetRandBits(1024)
	scale := new(big.Float).SetInt(r)
	max := new(big.Float).SetInt(new(big.Int).Lsh(big.NewInt(1), 1024))
	ratio, _ := new(big.Float).Quo(scale, max).Float64()
	return low + (high-low)*ratio
}

// RandRange 对照 Python randrange：支持 [start,stop) 与步长 step，
// 用 128bit 拒绝采样消除取模偏差（与源码同一思路，只是块宽不同）。
func (m *mtXOR25) RandRange(start, stop int64, step int64) int64 {
	if step == 0 {
		panic("mt_xor25: step cannot be zero")
	}
	if step < 0 {
		step = -step
	}
	span := stop - start
	if span <= 0 {
		panic("mt_xor25: stop must be greater than start")
	}
	cnt := (span-1)/step + 1
	maxU128 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	bias := new(big.Int).Mod(maxU128, big.NewInt(cnt))
	limit := new(big.Int).Sub(maxU128, bias)
	for {
		num := m.GetRandBits(128)
		if num.Cmp(limit) <= 0 {
			off := new(big.Int).Mod(num, big.NewInt(cnt)).Int64()
			return start + off*step
		}
	}
}

// RandInt 对照 Python randint(a,b)，返回闭区间 [a,b] 内的整数。
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
