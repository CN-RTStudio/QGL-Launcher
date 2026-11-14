package main

import (
	"encoding/binary"
	"math/big"
)

func (m *mtXOR25) GetRandBits(k int) *big.Int {
	if k <= 0 {
		panic("mt_xor25: bits must be positive")
	}
	res := new(big.Int)
	rem := k
	need := (rem + 0x7F) >> 7
	for i := 0; i < need; i++ {
		block := m.nextBlock()
		chunk := new(big.Int).SetBytes(block[:])
		take := 128
		if rem < take {
			take = rem
		}
		chunk.Rsh(chunk, uint(128-take))
		res.Lsh(res, uint(take))
		res.Or(res, chunk)
		rem -= take
	}
	return res
}

// randInt63n 返回 [0,n) 内近似无偏的随机数。用 64bit 拒绝采样，
// 保证 n 较小时不引入取模偏差。

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
