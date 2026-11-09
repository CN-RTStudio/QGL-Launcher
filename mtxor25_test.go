package main

import (
	"math/big"
	"testing"
)

// TestGetRandBitsRange 校验任意 bit 宽度的输出都落在 [0, 2^k) 内，
// 且非 128 整数倍宽度（如 7/100/200）也能正确取高位，不越界。
func TestGetRandBitsRange(t *testing.T) {
	m := globalMTXOR25()
	for _, k := range []int{1, 7, 8, 100, 127, 128, 129, 256, 1024} {
		v := m.GetRandBits(k)
		if v.Sign() < 0 {
			t.Fatalf("GetRandBits(%d) 出现负数", k)
		}
		upper := new(big.Int).Lsh(big.NewInt(1), uint(k))
		if v.Cmp(upper) >= 0 {
			t.Fatalf("GetRandBits(%d)=%s 超出 [0,2^k)", k, v.String())
		}
	}
}

// TestRandIntClosedRange 校验 randint 语义是闭区间 [a,b]，大量采样不越界。
func TestRandIntClosedRange(t *testing.T) {
	m := globalMTXOR25()
	const a, b = 3, 9
	seen := map[int64]int{}
	for i := 0; i < 4000; i++ {
		v := m.RandInt(a, b)
		if v < a || v > b {
			t.Fatalf("RandInt(%d,%d)=%d 越出闭区间", a, b, v)
		}
		seen[v]++
	}
	for n := int64(a); n <= b; n++ {
		if seen[n] == 0 {
			t.Fatalf("4000 次采样从未取到 %d，分布疑似异常", n)
		}
	}
}

// TestRandRangeStep 校验带步长时只返回合法网格上的点。
func TestRandRangeStep(t *testing.T) {
	m := globalMTXOR25()
	for i := 0; i < 2000; i++ {
		v := m.RandRange(2, 11, 3) // 合法点：2,5,8
		if v != 2 && v != 5 && v != 8 {
			t.Fatalf("RandRange(2,11,3)=%d 不在步长网格上", v)
		}
	}
}

// TestRandRangeInvalid 校验非法参数会 panic 而不是静默返回错误值。
func TestRandRangeInvalid(t *testing.T) {
	m := globalMTXOR25()
	bad := []struct{ a, b, s int64 }{
		{5, 5, 1},
		{9, 3, 1},
		{0, 10, 0},
	}
	for _, c := range bad {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("RandRange(%d,%d,%d) 应当 panic", c.a, c.b, c.s)
				}
			}()
			m.RandRange(c.a, c.b, c.s)
		}()
	}
}

// TestUniformRange 校验 uniform 输出落在 [low,high) 内。
func TestUniformRange(t *testing.T) {
	m := globalMTXOR25()
	for i := 0; i < 4000; i++ {
		v := m.Uniform(-2.5, 7.5)
		if v < -2.5 || v >= 7.5 {
			t.Fatalf("Uniform(-2.5,7.5)=%v 越界", v)
		}
	}
}

// TestRejectionSamplingUnbiased 粗略检验拒绝采样没有明显取模偏差：
// 对一个不能整除 2^128 的上界做大量采样，每个桶占比应接近均匀（容差较宽）。
func TestRejectionSamplingUnbiased(t *testing.T) {
	m := globalMTXOR25()
	const buckets int64 = 7
	const n = 21000
	counts := make([]int, buckets)
	for i := 0; i < n; i++ {
		counts[m.RandRange(0, buckets, 1)]++
	}
	ideal := n / int(buckets)
	for b, c := range counts {
		dev := c - ideal
		if dev < 0 {
			dev = -dev
		}
		// 允许 ±12% 的统计波动，远大于均匀分布的正常抖动。
		if dev > ideal*12/100 {
			t.Fatalf("桶 %d 计数 %d 偏离理想值 %d 过大，疑似取模偏差", b, c, ideal)
		}
	}
}
