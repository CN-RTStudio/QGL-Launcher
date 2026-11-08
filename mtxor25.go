package main

// mt_xor25 随机数生成器 —— bool-hybrid-array 生态移植（逐行对照 Python 源码
// bool_hybrid_array/core.py 中的 _real_generator / XOR25_Generator）。
//
// 与标准 MT19937 的区别（保持与 Python 实现一致）：
//  1. twist 中每个奇数 y 在异或 0x9908B0DF 之后，还会加上一个新的 OS 随机字节，
//     每次扭转都持续注入系统熵；
//  2. 输出不是单个回火字，而是回火字与后续 24 个状态字逐个异或的结果；
//  3. 异或结果（十进制字符串）先过 SHA3-512，再取 MD5 十六进制，每块 128 bit。
//
// 本文件只用于本地用途（重试抖动、临时随机量），不用于外部协议摘要。

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

const (
	mtN        = 624
	mtM        = 397
	mtMatrixA  = uint32(0x9908B0DF)
	mtUpperMask = uint32(0x80000000)
	mtLowerMask = uint32(0x7FFFFFFF)
	mtXorPeers = 24 // xor_result = 当前回火字 XOR 后续 24 个状态字
)

// mtXOR25 单实例自身加锁；全局单例见 globalMTXOR25。
type mtXOR25 struct {
	mu    sync.Mutex
	state [mtN]uint32
	index int
}

var (
	globalMT     *mtXOR25
	globalMTOnce sync.Once
)

// seedMTXOR25 完全照搬 Python 端的种子派生：
// 高精度时间 + 运行时/机器信息 + pid 等动态数据 + 8 字节 OS 随机数，
// 经 UMFS 256bit 摘要后取其 hex 文本再 MD5，最终只用 32 bit 播种 MT 状态。
func seedMTXOR25() *mtXOR25 {
	var entropy [8]byte
	_, _ = rand.Read(entropy[:])
	mix := strconv.FormatInt(time.Now().UnixNano(), 10) +
		runtime.Version() + runtime.GOARCH + runtime.GOOS + strconv.Itoa(runtime.NumCPU()) +
		fmt.Sprintf("_%d_", os.Getpid()) +
		hex.EncodeToString(entropy[:])

	h1 := NewUMFS([]byte(mix)).Digest()
	h2 := md5.Sum([]byte(fmt.Sprintf("%x", h1)))

	m := &mtXOR25{index: mtN + 1}
	m.state[0] = binary.BigEndian.Uint32(h2[:4])
	for i := 1; i < mtN; i++ {
		prev := m.state[i-1]
		m.state[i] = uint32(1812433253*(uint64(prev)^uint64(prev>>30))+uint64(i))
	}
	m.index = mtN // 首次取值前强制 twist
	return m
}

func globalMTXOR25() *mtXOR25 {
	globalMTOnce.Do(func() { globalMT = seedMTXOR25() })
	return globalMT
}

// twist 对照 Python：奇数 y 先异或矩阵常数，再加一个新的 OS 随机字节。
func (m *mtXOR25) twist() {
	var oneByte [1]byte
	for i := 0; i < mtN; i++ {
		y := (m.state[i] & mtUpperMask) + (m.state[(i+1)%mtN]&mtLowerMask)
		m.state[i] = m.state[(i+mtM)%mtN] ^ (y >> 1)
		if y&1 != 0 {
			m.state[i] ^= mtMatrixA
			_, _ = rand.Read(oneByte[:])
			m.state[i] += uint32(oneByte[0])
		}
	}
	m.index = 0
}

// nextBlock 生成一块 128bit 随机输出（MD5 hex 的 16 字节形态）。
// 注意 peer 下标从 index+1 开始（Python 循环 i=1..24，index 已自增）。
func (m *mtXOR25) nextBlock() [16]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.index >= mtN {
		m.twist()
	}
	y := m.state[m.index]
	m.index++
	y ^= y >> 11
	y ^= (y << 7) & 0x9D2C5680
	y ^= (y << 15) & 0xEFC60000
	y ^= y >> 18

	xorResult := uint64(y)
	for i := 1; i <= mtXorPeers; i++ {
		xorResult ^= uint64(m.state[(m.index+i)%mtN])
	}

	var h3 [64]byte = sha3.Sum512([]byte(strconv.FormatUint(xorResult, 10)))
	return md5.Sum(h3[:])
}

// GetRandBits 对照 Python getrandbits：按每块 128bit、高位优先拼接。
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
func mtXor25Uniform(low, high float64) float64 { return globalMTXOR25().Uniform(low, high) }
func mtXor25RandInt(a, b int64) int64          { return globalMTXOR25().RandInt(a, b) }

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
