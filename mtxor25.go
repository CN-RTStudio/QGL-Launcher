package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/sha3"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
)

const (
	mtN         = 624
	mtM         = 397
	mtMatrixA   = uint32(0x9908B0DF)
	mtUpperMask = uint32(0x80000000)
	mtLowerMask = uint32(0x7FFFFFFF)
	mtXorPeers  = 24 // xor_result = 当前回火字 XOR 后续 24 个状态字
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
		m.state[i] = uint32(1812433253*(uint64(prev)^uint64(prev>>30)) + uint64(i))
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
		y := (m.state[i] & mtUpperMask) + (m.state[(i+1)%mtN] & mtLowerMask)
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
